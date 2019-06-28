/*-------------------------------------------------------------------------
 *
 * copydir.c
 *	  copies a directory
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *	While "xcopy /e /i /q" works fine for copying directories, on Windows XP
 *	it requires a Window handle which prevents it from working when invoked
 *	as a service.
 *
 * IDENTIFICATION
 *	  src/backend/storage/file/copydir.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "storage/copydir.h"
#include "storage/encryption.h"
#include "storage/fd.h"
#include "storage/kmgr.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "utils/spccache.h"

static void reencrypt_copy_buffer(char *buffer, int nbytes, RelFileNode srcNode,
								  RelFileNode dstNode, BlockNumber blkno_inseg,
								  ForkNumber forknum);
/*
 * copydir: copy a directory
 *
 * If recurse is false, subdirectories are ignored.  Anything that's not
 * a directory or a regular file is ignored.
 */
void
copydir(char *fromdir, char *todir, bool recurse)
{
	DIR		   *xldir;
	struct dirent *xlde;
	char		fromfile[MAXPGPATH * 2];
	char		tofile[MAXPGPATH * 2];

	if (MakePGDirectory(todir) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not create directory \"%s\": %m", todir)));

	xldir = AllocateDir(fromdir);

	while ((xlde = ReadDir(xldir, fromdir)) != NULL)
	{
		struct stat fst;

		/* If we got a cancel signal during the copy of the directory, quit */
		CHECK_FOR_INTERRUPTS();

		if (strcmp(xlde->d_name, ".") == 0 ||
			strcmp(xlde->d_name, "..") == 0)
			continue;

		snprintf(fromfile, sizeof(fromfile), "%s/%s", fromdir, xlde->d_name);
		snprintf(tofile, sizeof(tofile), "%s/%s", todir, xlde->d_name);

		if (lstat(fromfile, &fst) < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not stat file \"%s\": %m", fromfile)));

		if (S_ISDIR(fst.st_mode))
		{
			/* recurse to handle subdirectories */
			if (recurse)
				copydir(fromfile, tofile, true);
		}
		else if (S_ISREG(fst.st_mode))
			copy_file(fromfile, tofile);
	}
	FreeDir(xldir);

	/*
	 * Be paranoid here and fsync all files to ensure the copy is really done.
	 * But if fsync is disabled, we're done.
	 */
	if (!enableFsync)
		return;

	xldir = AllocateDir(todir);

	while ((xlde = ReadDir(xldir, todir)) != NULL)
	{
		struct stat fst;

		if (strcmp(xlde->d_name, ".") == 0 ||
			strcmp(xlde->d_name, "..") == 0)
			continue;

		snprintf(tofile, sizeof(tofile), "%s/%s", todir, xlde->d_name);

		/*
		 * We don't need to sync subdirectories here since the recursive
		 * copydir will do it before it returns
		 */
		if (lstat(tofile, &fst) < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not stat file \"%s\": %m", tofile)));

		if (S_ISREG(fst.st_mode))
			fsync_fname(tofile, false);
	}
	FreeDir(xldir);

	/*
	 * It's important to fsync the destination directory itself as individual
	 * file fsyncs don't guarantee that the directory entry for the file is
	 * synced. Recent versions of ext4 have made the window much wider but
	 * it's been true for ext3 and other filesystems in the past.
	 */
	fsync_fname(todir, true);
}

/*
 * copy one file
 */
void
copy_file(char *fromfile, char *tofile)
{
	char	   *buffer;
	int			srcfd;
	int			dstfd;
	int			nbytes;
	off_t		offset;
	off_t		flush_offset;
	RelFileNode fromNode;
	RelFileNode toNode;
	ForkNumber	forknum;
	BlockNumber	segment;
	bool		need_encryption;

	/* Size of copy buffer (read and write requests) */
#define COPY_BUF_SIZE (8 * BLCKSZ)

	/*
	 * Size of data flush requests.  It seems beneficial on most platforms to
	 * do this every 1MB or so.  But macOS, at least with early releases of
	 * APFS, is really unfriendly to small mmap/msync requests, so there do it
	 * only every 32MB.
	 */
#if defined(__darwin__)
#define FLUSH_DISTANCE (32 * 1024 * 1024)
#else
#define FLUSH_DISTANCE (1024 * 1024)
#endif

	/* Use palloc to ensure we get a maxaligned buffer */
	buffer = palloc(COPY_BUF_SIZE);

	/*
	 * Open the files
	 */
	srcfd = OpenTransientFile(fromfile, O_RDONLY | PG_BINARY);
	if (srcfd < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open file \"%s\": %m", fromfile)));

	dstfd = OpenTransientFile(tofile, O_RDWR | O_CREAT | O_EXCL | PG_BINARY);
	if (dstfd < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not create file \"%s\": %m", tofile)));

	/*
	 * Encryption while copying is needed when the target file is a relation file
	 * and either from file or to file is encrypted.
	 */
	need_encryption = ParseRelationPath(fromfile, &(fromNode.dbNode),
										&(fromNode.spcNode),
										&(fromNode.relNode),
										&forknum, &segment);
	ParseRelationPath(tofile, &(toNode.dbNode),
					  &(toNode.spcNode), &(toNode.relNode),
					  &forknum, &segment);
        need_encryption &= (realtion_is_encrypted(fromNode.relNode) ||
                                                realtion_is_encrypted(toNode.relNode));
//	need_encryption &= (tablespace_is_encrypted(fromNode.spcNode) ||
//						tablespace_is_encrypted(toNode.spcNode));

#ifdef DEBUG_TDE
	fprintf(stderr, "copydir::copy file \"%s\"d = %u, s = %u, r = %u, enc = %d\n",
			tofile, toNode.dbNode, toNode.spcNode, toNode.relNode,
			need_encryption);
#endif
	/*
	 * Do the data copying.
	 */
	flush_offset = 0;
	for (offset = 0;; offset += nbytes)
	{
		/* If we got a cancel signal during the copy of the file, quit */
		CHECK_FOR_INTERRUPTS();

		/*
		 * We fsync the files later, but during the copy, flush them every so
		 * often to avoid spamming the cache and hopefully get the kernel to
		 * start writing them out before the fsync comes.
		 */
		if (offset - flush_offset >= FLUSH_DISTANCE)
		{
			pg_flush_data(dstfd, flush_offset, offset - flush_offset);
			flush_offset = offset;
		}

		pgstat_report_wait_start(WAIT_EVENT_COPY_FILE_READ);
		nbytes = read(srcfd, buffer, COPY_BUF_SIZE);
		pgstat_report_wait_end();
		if (nbytes < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not read file \"%s\": %m", fromfile)));
		if (nbytes == 0)
			break;
		errno = 0;

		/* Encrypt buffer data */
		if (TransparentEncryptionEnabled() && need_encryption)
		{
			BlockNumber blkno_inseg = offset / BLCKSZ;

			reencrypt_copy_buffer(buffer, nbytes, fromNode, toNode,
								  blkno_inseg, forknum);
		}

		pgstat_report_wait_start(WAIT_EVENT_COPY_FILE_WRITE);
		if ((int) write(dstfd, buffer, nbytes) != nbytes)
		{
			/* if write didn't set errno, assume problem is no disk space */
			if (errno == 0)
				errno = ENOSPC;
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not write to file \"%s\": %m", tofile)));
		}
		pgstat_report_wait_end();
	}

	if (offset > flush_offset)
		pg_flush_data(dstfd, flush_offset, offset - flush_offset);

	if (CloseTransientFile(dstfd))
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not close file \"%s\": %m", tofile)));

	if (CloseTransientFile(srcfd))
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not close file \"%s\": %m", fromfile)));

	pfree(buffer);
}

/*
 * 'buffer' has 'nbytes' data of block data starting from 'blkno' block number
 */
static void
reencrypt_copy_buffer(char *buffer, int nbytes, RelFileNode srcNode,
					  RelFileNode dstNode, BlockNumber blkno_inseg,
					  ForkNumber forknum)
{
	BlockNumber curblkno = blkno_inseg;
	BlockNumber nblocks = nbytes / BLCKSZ;
	char		srcTweak[ENCRYPTION_TWEAK_SIZE] = {0};
	char		dstTweak[ENCRYPTION_TWEAK_SIZE] = {0};
	char		*cur;
//	bool		srcisencrypted = tablespace_is_encrypted(srcNode.spcNode);
//	bool		dstisencrypted = tablespace_is_encrypted(dstNode.spcNode);
	bool            srcisencrypted = realtion_is_encrypted(srcNode.relNode);
	bool            dstisencrypted = realtion_is_encrypted(dstNode.relNode);

	Assert(nbytes % BLCKSZ == 0);

	for (cur = buffer; cur < buffer + (nblocks * BLCKSZ);
		 cur += BLCKSZ)
	{
		if (srcisencrypted)
		{
			BufferEncryptionTweak(srcTweak, &srcNode, forknum, curblkno);
			DecryptBufferBlock(srcNode.spcNode, srcTweak, cur, cur);
		}

		if (dstisencrypted)
		{
			BufferEncryptionTweak(dstTweak, &dstNode, forknum, curblkno);
			EncryptBufferBlock(dstNode.spcNode, dstTweak, cur, cur);
		}
		curblkno++;
	}
}
