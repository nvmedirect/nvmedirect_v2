#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <dirent.h>
#include <pthread.h> //#include <unistd.h>

typedef enum {
	IOENGINE_NONE = 0,
	IOENGINE_LINUX,
	IOENGINE_USER
} WRAPPER_STORAGE_ENGINE;

typedef enum {
	FSENGINE_NONE = 0,
	FSENGINE_LINUX,
	FSENGINE_USER
} WRAPPER_FILESYSTEM_ENGINE;

struct io_init_opt {
	const char *path;
	const char *dev_path;

	void *opt;
};

struct fs_init_opt {
	const char *path;
	
	const char *dev_path;
	int meta_ratio;

	void *opt;

	struct io_ops *io_ops;
};

struct io_ops {
	//init (arg? target)
	//finalize
	//create queue
	//destroy queue
	//read
	//write
	//discard
	
	int		(*init)(struct io_init_opt *opt);
	int		(*finalize)(void);
	ssize_t	(*read)(void *buf, size_t count, off_t offset);
	ssize_t	(*write)(void *buf, size_t count, off_t offset);
	ssize_t	(*d_read)(void *buf, size_t count, off_t offset);
	ssize_t	(*d_write)(void *buf, size_t count, off_t offset);
	ssize_t	(*discard)(size_t count, off_t offset);

	const char *engine_name;
};

struct linux_dirent {
	unsigned long  d_ino;     /* Inode number */
	unsigned long  d_off;     /* Offset to next linux_dirent */
	unsigned short d_reclen;  /* Length of this linux_dirent */
	char           d_name[];  /* Filename (null-terminated) */
	/* length is actually (d_reclen - 2 -
	   offsetof(struct linux_dirent, d_name)) */
	/*
	   char           pad;       // Zero padding byte
	   char           d_type;    // File type (only since Linux
	// 2.6.4); offset is (d_reclen - 1)
	*/

};

struct fs_ops {
	int		(*open)(const char *pathname, int flags);
	ssize_t (*read)(int fd, void *buf, size_t count);
	ssize_t (*write)(int fd, const void *buf, size_t count);
	int		(*close)(int fd);
	int		(*__xstat)(int ver, const char *path, struct stat *stat_buf);
	int		(*__lxstat)(int ver, const char * path, struct stat *stat_buf);
	int		(*__fxstat)(int ver, int fd, struct stat *stat_buf);
	int		(*__xstat64)(int ver, const char *path, struct stat64 *stat_buf);
	int		(*__lxstat64)(int ver, const char * path, struct stat64 *stat_buf);
	int		(*__fxstat64)(int ver, int fd, struct stat64 *stat_buf);
	off_t	(*lseek)(int fd, off_t offset, int whence);
	ssize_t (*pread)(int fd, void *buf, size_t count, off_t offset);
	ssize_t (*pwrite)(int fd, const void *buf, size_t count, off_t offset);
	int		(*fallocate)(int fd, int mode, off_t offset, off_t len);
	int		(*access)(const char *pathname, int mode);
	int		(*fcntl)(int fd, int cmd, ... /* arg */ );
	int		(*flock)(int fd, int operation);
	int		(*fsync)(int fd);
	int		(*fdatasync)(int fd);
	int		(*truncate)(const char *path, off_t length);
	int		(*ftruncate)(int fd, off_t length);
	int		(*rename)(const char *oldpath, const char *newpath);
	int		(*mkdir)(const char *pathname, mode_t mode);
	int		(*rmdir)(const char *pathname);
	int		(*sync)(void);
	int		(*syncfs)(int fd);

	DIR*	(*opendir)(const char *name);
	struct dirent* (*readdir)(DIR *dirp);
	int		(*readdir64_r) (DIR *__restrict __dirp,
				struct dirent64 *__restrict __entry,
				struct dirent64 **__restrict __result);

	int		(*closedir)(DIR *dirp);

	//int		(*openat)(int dirfd, const char *pathname, int flags);
	//int		(*getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

	int		(*init)(struct fs_init_opt *opt);
	int		(*finalize)(void);
	
	int		(*format)(struct fs_init_opt *opt);
	
	const char	*fs_name;
};

FILE *(*orig_fopen64)(const char *path, const char *mode);
int (*orig_fclose)(FILE *fp);
size_t (*orig_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t (*orig_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream);


int nr_dirp_list;
DIR** dirp_list;
pthread_spinlock_t dirp_list_lock;

struct fs_ops *fs_ops;
void *fs_ops_dlhandle;
struct io_ops *io_ops;
void *io_ops_dlhandle;

bool req_format;

// Default I/O Handler
struct fs_ops fs_ops_linux;

/////////////////////////////
// FD (file descriptor) rule
/////////////////////////////
// Linux : system default
// User File System : start with MAX_FD (ulimit) + 1
/////////////////////////////
long long USR_FD_START;

char *USR_ABS_DIR;
size_t USR_ABS_DIR_LEN;
char *USR_DIR;
size_t USR_DIR_LEN;
char *USR_DIR_PARENT;
size_t USR_DIR_PARENT_LEN;
