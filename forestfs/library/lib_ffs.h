/**********************************************************
 * ForestFS Library & Structures
 *********************************************************/

#ifndef _FORESTFS_LIB_H_
#define _FORESTFS_LIB_H_

#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <lib_nvmed.h>
#include <libforestdb/forestdb.h>

#define FFS_BLK_SIZE 4096
#define FDB_DATA_IN_BLK (4096-16)

#define NUM_EXTENTS_IN_INODE 4
//last one is pointing the next extents block
#define NUM_EXTENTS_IN_BLKS (FFS_BLK_SIZE / sizeof(FFS_EXTENTS) - 1)

typedef int FFS_STATUS;
typedef unsigned int FFS_INODE_TYPE;
typedef unsigned int FFS_IO;
typedef int FFS_FD;

#ifndef USR_IO_ENGINE_ENUM
#define USR_IO_ENGINE_ENUM
enum IO_ENGINE {
	LINUX		= 0,
	NVMeDirect,
};
#endif

enum NVMeDirect_Handle_Type {
	NVMeDirect_SYNC = 0,
	NVMeDirect_ASYNC,
};

struct ffs_sb {
	uint64_t num_fs_blocks;
	uint64_t num_meta_blocks;
	uint64_t num_data_blocks;
	uint64_t num_free_blocks;
	uint32_t num_bmap_blocks;
};
typedef struct ffs_sb FFS_SB;

struct ffs_root {
	char *path;
	int fd;
	uint32_t max_file_descriptor;
	uint32_t prealloc_blks;
	bool auto_sync;

	fdb_file_handle *fhandle;
	fdb_kvs_handle *kvhandle;
	fdb_config db_config;
	fdb_kvs_config kvs_config;

	unsigned int storage_engine;
	union {
		struct NVMeDirect {
			NVMED *nvmed;
			NVMED_QUEUE *queue[2];
			NVMED_HANDLE *handle[2];
		} nvmedirect;
	} storage_data;

	FFS_SB *ffs_sb;
	pthread_spinlock_t meta_lock;
	pthread_spinlock_t blkmap_lock;

	pthread_spinlock_t fd_map;
};
typedef struct ffs_root FFS_ROOT;

struct ffs_format_config {
	uint64_t fs_size;
	uint32_t meta_ratio;
};
typedef struct ffs_format_config FFS_FORMAT_CONFIG;

struct ffs_init_config {
	uint32_t max_file_descriptor;
	bool	 auto_sync;
	uint32_t prealloc_blks;
	
	unsigned int storage_engine;
};
typedef struct ffs_init_config FFS_INIT_CONFIG;

struct ffs_extents {
	uint32_t ext_block;
	uint32_t ext_len;
	uint64_t phys_block;
};
typedef struct ffs_extents FFS_EXTENTS;

enum FFS_INODE_TYPE {
	FFS_TYPE_REGULAR = 0,
	FFS_TYPE_DIRECTORY,
};

struct ffs_inode {
	FFS_INODE_TYPE type;
	off_t     size;
	unsigned long blocks;
	time_t    atime;
	time_t    mtime;
	time_t    ctime;
	uint32_t	num_extents;
	uint32_t	ref;
	bool		isDelete;
	FFS_EXTENTS extents[NUM_EXTENTS_IN_INODE];
};
typedef struct ffs_inode FFS_INODE;

struct ffs_fd_info {
	FFS_INODE* ffs_inode;
	char*	path;
	off_t	pos;
	int		flags;
	int		is_dirp;
	void*	opt;
};
typedef struct ffs_fd_info FFS_FD_INFO;

struct ffs_iovec {
	uint64_t start_block;
	off_t offset;
	size_t count;
	void* buf;

	struct ffs_iovec* next;
};
typedef struct ffs_iovec FFS_IOVEC;

struct ffs_dir {
	int fd;
	fdb_iterator *iterator;
	struct dirent dir;
	int curPos;
};
typedef struct ffs_dir FFS_DIR;

enum {
	FFS_RESULT_SUCCESS		= 0,
	FFS_RESULT_FAIL 		= -1,
	FFS_RESULT_NOENT 		= -2,
	FFS_RESULT_NOPERM		= -3,
};

enum FFS_IO {
	FFS_IO_WRITE 	= 0,
	FFS_IO_READ		= 1,
	FFS_IO_DISCARD	= 2,
};

//FFS_IO_LINUX
//FFS_IO_NVMED

//FFS_STATUS ffs_init(const char* path, FFS_INIT_CONFIG* config);
//FFS_STATUS ffs_finalize();
//FFS_STATUS ffs_format(const char* path, FFS_FORMAT_CONFIG* config);

//FFS_FD ffs_open(const char* path, int flags);
FFS_STATUS ffs_close(FFS_FD fd);

int ffs_access(const char* pathname, int mode);

int ffs_mkdir(const char* pathname, mode_t mode);
int ffs_rmdir(const char* pathname);

//ssize_t ffs_read(FFS_FD fd, void* buf, size_t count);
//ssize_t ffs_write(FFS_FD fd, void* buf, size_t count);
FFS_STATUS ffs_fstat(FFS_FD fd, struct stat *buf);
FFS_STATUS ffs_stat(const char *path, struct stat *buf);
#define ffs_lstat(path, buf) ffs_stat(path, buf);
off_t ffs_lseek(FFS_FD fd, off_t offset, int whence);
FFS_STATUS ffs_ftruncate(FFS_FD fd, off_t length);
FFS_STATUS ffs_unlink(const char* path);
FFS_STATUS ffs_rename(const char* orig, const char* dest);
FFS_STATUS ffs_remove_inode(const char* path);

//ssize_t ffs_pread(FFS_FD fd, void* buf, size_t count, off_t offset);
//ssize_t ffs_pwrite(FFS_FD fd, void* buf, size_t count, off_t offset);

int ffs_sync();
int ffs_fsync(FFS_FD fd);
int ffs_fdatasync(FFS_FD fd);

DIR* ffs_opendir(const char *path);
struct dirent* ffs_readdir(DIR *_dirp);
FFS_STATUS ffs_closedir(DIR *_dirp);

#endif
