/*-------------------------------------------------------------------------
 *
 * relencmap.c
 *	 This module records object encryption.
 *
 * Copyright (c) 2019, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/storage/kmgr/relencmap.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <unistd.h>

#include "funcapi.h"
#include "miscadmin.h"

#include "access/xlog.h"
#include "storage/encryption.h"
#include "storage/fd.h"
#include "storage/kmgr.h"
#include "storage/kmgr_plugin.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/builtins.h"
#include "utils/hsearch.h"
#include "utils/memutils.h"
#include "utils/inval.h"
#include "utils/syscache.h"

/* Struct for one relenc map */
#define RELFILENODE_ENC_MAP "pg_relenc.map"

/*
 * Shared variables.  The following shared variables are protected by
 * KeyringControlLock.
*/
static HTAB			*RelEncMap;
MemoryContext relencmapContext;

static bool load_relencmap_file(void);
static void read_relencmap_file(List **maplist_p);
static void update_relencmap_file(bool filled);
/*
 * Initialize Kmgr and kmgr plugin. We load the keyring file and set up both
 * KmgrCtl and TblspcKeyring hash table on shared memory. When first time to
 * access the keyring file, ie the keyring file does not exist, we create it
 * with the initial master key id. If the keyring file exists, we load it to
 * the shared structs. This function must be called by postmaster at startup
 * time.
 */
void
InitializeREM(void)
{
	HASHCTL         hash_ctl;

	if (!TransparentEncryptionEnabled())
		return;

	if (RelEncMap)
	{
		hash_destroy(RelEncMap);
		RelEncMap = NULL;
	}

	/*
	 * Invoke kmgr plugin startup callback. Since we could get the master key
	 * during loading the keyring file we have to startup the plugin beforehand.
	 */
	ereport(DEBUG1, (errmsg("invoking kmgr plugin startup callback")));

	if (!relencmapContext)
		relencmapContext = AllocSetContextCreate(TopMemoryContext,
													"Relfilenode Encryption Map",
													ALLOCSET_DEFAULT_SIZES);

        memset(&hash_ctl, 0, sizeof(hash_ctl));
        hash_ctl.keysize = sizeof(Oid);
        hash_ctl.entrysize = sizeof(Oid);
        hash_ctl.hcxt = relencmapContext;
        RelEncMap = hash_create("Relfilenode Encryption Map",
                                           1000,
                                           &hash_ctl,
                                           HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);
	/* Load keyring file and update shmem structs */
	if (!load_relencmap_file())
	{
	//	LWLockAcquire(KeyringControlLock, LW_EXCLUSIVE);
		update_relencmap_file(true);
	//	LWLockRelease(KeyringControlLock);
	}
}

/*
 * Check the tablespace key is exists. Since encrypted tablespaces has its
 * encryption key this function can be used to check if the tablespace is
 * encrypted.
 */
bool
RelEncMapExists(Oid relfilenode)
{
	bool		found;

	Assert(OidIsValid(relfilenode));

	(void *) hash_search(RelEncMap, (void *) &relfilenode, HASH_FIND, &found);

	return found;
}

/*
 * Drop one tablespace key from the keyring hash table and update the keyring
 * file.
 */
void
RelEncMapDelete(Oid relfilenode)
{
	bool found;

	LWLockAcquire(KeyringControlLock, LW_EXCLUSIVE);

	hash_search(RelEncMap, (void *) &relfilenode, HASH_REMOVE, &found);

	if (!found)
		elog(ERROR, "could not find tablespace encryption key for tablespace %u",
			 relfilenode);

	LWLockRelease(KeyringControlLock);
	/* Update tablespace key file */
	update_relencmap_file(false);
}

/*
 * Add a tablespace key of given tablespace to the keyring hash table.
 * *encrrypted_key is encrypted with the encryption key identified by
 * masterkeyid. If the encryption key of the tablespace already exists,
 * we check if these keys are the same.
 */
void
RelEncMapAdd(Oid relfilenode)
{
	bool	found;

//	LWLockAcquire(KeyringControlLock, LW_EXCLUSIVE);

	hash_search(RelEncMap, (void *) &relfilenode, HASH_ENTER,
					  &found);

	if (found)
	{
		LWLockRelease(KeyringControlLock);

			elog(WARNING, "adding encryption key for tablespace %u does not match the exsiting one",
				relfilenode);

		/* The existing key is the same, return */
		return;
	}

	update_relencmap_file(false);

//	LWLockRelease(KeyringControlLock);
}

/*
 * Load the keyring file and update the shared variables. This function is
 * intended to be used by postmaster at startup time , so lockings are not
 * needed.
 */
static bool
load_relencmap_file(void)
{
	List *maplist = NIL;
	ListCell *lc;

	/* Read relencmap file */
	read_relencmap_file(&maplist);

	/* There is no keyring file */
	if (maplist == NULL)
	{
		return false;
	}

	/* Loading tablespace keys to shared keyring hash table */
	foreach (lc, maplist)
	{
		Oid map_infile = lfirst_oid(lc);

		hash_search(RelEncMap, (void *) &map_infile, HASH_ENTER, NULL);
	}

	list_free(maplist);

	return true;
}

/*
 * Read the keyring file and return the list of tablespace keys.
 */
static void
read_relencmap_file(List **maplist_p)
{
	char *path = "global/"RELFILENODE_ENC_MAP;
	int read_len;
	int fd;

	fd = OpenTransientFile(path, O_RDONLY | PG_BINARY);

	if (fd < 0)
	{
		if (errno == ENOENT)
			return NULL;

		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open file \"%s\": %m", path)));
	}

	for (;;)
	{
		Oid mapc;

		read_len = read(fd, &mapc, sizeof(Oid));

		if (read_len < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 (errmsg("could not read from file \"%s\": %m", path))));
		else if (read_len == 0) /* EOF */
			break;
		else if (read_len != sizeof(Oid))
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not read from file \"%s\": read %d instead of %u bytes",
							path, read_len, sizeof(Oid))));
		*maplist_p = lappend_oid(*maplist_p, mapc);
	}

	CloseTransientFile(fd);
}

static void
update_relencmap_file(bool filled)
{
	HASH_SEQ_STATUS status;
	Oid map;
	Oid *mapp;
	char path[MAXPGPATH];
	char tmppath[MAXPGPATH];
	FILE *fpout;
	int	rc;
	Oid first = 0;


//	Assert(LWLockHeldByMeInMode(KeyringControlLock, LW_EXCLUSIVE));

	sprintf(path, "global/"RELFILENODE_ENC_MAP);
	sprintf(tmppath, "global/"RELFILENODE_ENC_MAP".tmp");

	fpout = AllocateFile(tmppath, PG_BINARY_W);
	if (fpout == NULL)
	{
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not open temporary keyring file \"%s\": %m",
						tmppath)));
		return;
	}

	if(filled)
		rc = fwrite(&first, sizeof(Oid), 1, fpout);

	/* If we have any tablespace keys, write them to the file.  */
	if (hash_get_num_entries(RelEncMap) > 0)
	{
		/* Write tablespace map to the file */
		hash_seq_init(&status, RelEncMap);
		while (((mapp) = (void *) hash_seq_search(&status)) != NULL)
		{
			rc = fwrite(mapp, sizeof(Oid), 1, fpout);
			(void) rc; /* will check for error with ferror */
		}
	}

	if (ferror(fpout))
	{
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not write temporary keyring file \"%s\": %m",
						tmppath)));
		FreeFile(fpout);
		unlink(tmppath);
	}
	else if (FreeFile(fpout) < 0)
	{
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not close temporary keyring file \"%s\": %m",
						tmppath)));
		unlink(tmppath);
	}
	else if (durable_rename(tmppath, path, ERROR) < 0)
	{
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not rename temporary keyring file \"%s\" to \"%s\": %m",
						tmppath, path)));
		unlink(tmppath);
	}
}
