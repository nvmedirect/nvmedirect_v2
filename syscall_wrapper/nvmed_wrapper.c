#include "nvmed_wrapper.h"
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <sys/resource.h>
#include <libgen.h>

#define ofn(ptr, fn) ptr . fn
#define setup_default_handler(ptr, fn) \
	ofn(ptr, fn) = dlsym(RTLD_NEXT, #fn); \
if(ofn(ptr, fn) == NULL) { \
	temp_handle = dlopen("libselinux.so.1", RTLD_NOW); \
	ofn(ptr, fn) = dlsym(temp_handle,#fn); \
	if(ofn(ptr, fn) == NULL) { \
		fprintf(stderr, "Wrapper-%s: %s\n", #fn, dlerror()); \
	} \
	dlclose(temp_handle); \
}
#define setup_fs_handler(ptr, ops, fn) ofn(ptr, ops) = fn
#define setup_handler_name(dest, src) dest . fs_name = src
#define setup_handler(handler) fs_ops = &handler

#define config_opts(val) if(!strcmp(val, opt))
#define config_opt(val) else if(!strcmp(val, opt))

static void init_io_constructor(void) __attribute__((constructor));
static void final_io_destructor(void) __attribute__((destructor));
WRAPPER_STORAGE_ENGINE storage_engine = 0;
WRAPPER_FILESYSTEM_ENGINE fs_engine = 0;

int meta_ratio = 0;
const char *storage_dev = NULL;

void setup_io_engine_linux(void) {
	void *temp_handle;
	setup_default_handler(fs_ops_linux, open);
	setup_default_handler(fs_ops_linux, read);
	setup_default_handler(fs_ops_linux, write);
	setup_default_handler(fs_ops_linux, close);
	setup_default_handler(fs_ops_linux, __xstat);
	setup_default_handler(fs_ops_linux, __xstat64);
	setup_default_handler(fs_ops_linux, __lxstat);
	setup_default_handler(fs_ops_linux, __lxstat64);
	setup_default_handler(fs_ops_linux, __fxstat);
	setup_default_handler(fs_ops_linux, __fxstat64);
	setup_default_handler(fs_ops_linux, lseek);
	setup_default_handler(fs_ops_linux, pread);
	setup_default_handler(fs_ops_linux, pwrite);
	setup_default_handler(fs_ops_linux, fallocate);
	setup_default_handler(fs_ops_linux, access);
	setup_default_handler(fs_ops_linux, fcntl);
	setup_default_handler(fs_ops_linux, flock);
	setup_default_handler(fs_ops_linux, fsync);
	setup_default_handler(fs_ops_linux, fdatasync);
	setup_default_handler(fs_ops_linux, truncate);
	setup_default_handler(fs_ops_linux, ftruncate);
	setup_default_handler(fs_ops_linux, rename);
	setup_default_handler(fs_ops_linux, mkdir);
	setup_default_handler(fs_ops_linux, rmdir);
	setup_default_handler(fs_ops_linux, sync);
	setup_default_handler(fs_ops_linux, syncfs);

	setup_default_handler(fs_ops_linux, opendir);
	setup_default_handler(fs_ops_linux, readdir);
	setup_default_handler(fs_ops_linux, readdir64_r);
	setup_default_handler(fs_ops_linux, closedir);

	//setup_default_handler(fs_ops_linux, openat);
	//setup_default_handler(fs_ops_linux, getdents);
	
	setup_fs_handler(fs_ops_linux, init, NULL);
	setup_fs_handler(fs_ops_linux, finalize, NULL);

	setup_fs_handler(fs_ops_linux, format, NULL);

	setup_handler_name(fs_ops_linux, "LINUX");

	orig_fopen64 = dlsym(RTLD_NEXT, "fopen64");
	orig_fclose = dlsym(RTLD_NEXT, "fclose");
	orig_fread = dlsym(RTLD_NEXT, "fread");
	orig_fwrite = dlsym(RTLD_NEXT, "fwrite");

	setup_handler(fs_ops_linux);
}

void setup_io_dir(const char* path) {
	char abs_path[PATH_MAX];

	realpath(path, abs_path);
	USR_ABS_DIR = strdup(abs_path);
	USR_ABS_DIR_LEN = strlen(USR_ABS_DIR);

	USR_DIR = strdup(path);
	USR_DIR_LEN = strlen(USR_DIR);

	USR_DIR_PARENT = strdup(dirname(abs_path));
	USR_DIR_PARENT_LEN = strlen(USR_DIR_PARENT);

	fprintf(stderr, "===> %s\n", USR_DIR_PARENT);
}

void wrapper_config(const char* path) {
	FILE *fp;
	char line_buf[1024];
	char *opt, *val;
	
	void* dlhandle;
	bool err = 0;
	
	bool opt_pass = false;
	req_format = false;

	fp = fopen(path, "r");
	if(fp == NULL) {
		fprintf(stderr, "Error on reading config file(%d): %s\n", 
				errno, path);
		fprintf(stderr, "Use LINUX Default I/O functions\n");
		return;
	}

	while(fgets(line_buf, 1024, fp)) {
		if(line_buf[strlen(line_buf)-1] == '\n')
			line_buf[strlen(line_buf)-1] = '\0';
	
		if(line_buf[0] == '=') opt_pass=!opt_pass;
		if(line_buf[0] == '=' || line_buf[0] == '\0' || line_buf[0] == '#'
				|| opt_pass) continue;

		opt = strtok(line_buf, "=");
		val = strtok(NULL, "=");
		
		while(opt[0] == ' ') opt++;
		while(opt[strlen(opt)-1] == ' ') opt[strlen(opt)-1] = '\0';
		while(val[0] == ' ') val++;
		while(val[strlen(opt)-1] == ' ') val[strlen(val)-1] = '\0';

		config_opts("storage_engine") {
			if(!strcmp("linux", val)) {
				storage_engine = IOENGINE_LINUX;
				setup_io_engine_linux();
			}
			else {
				storage_engine = IOENGINE_USER;
				io_ops = NULL;
			}
			/*
			else {
				dlhandle = dlopen(val, RTLD_LAZY);
				if (!dlhandle) {
					fprintf(stderr, "Error on Dynamic linking Storage engine : %s\n",
							val);
					err = true;
				}

				io_ops = dlsym(dlhandle, "io_ops");
				if(!io_ops) {
					fprintf(stderr, "Error on Linking Storage engine Operations : %s\n",
							val);
					err = true;
				}

				if(!err) {
					io_ops_dlhandle = dlhandle;
					storage_engine = IOENGINE_USER;
				}
			}
			*/
		}
		config_opt("storage_dev") {
			storage_dev = strdup(val);
		}
		config_opt("filesystem") {
			if(!strcmp("linux", val)) {
				fs_engine = FSENGINE_LINUX;
				setup_io_engine_linux();
			}
			else {
				dlhandle = dlopen(val, RTLD_LAZY);
				if (!dlhandle) {
					fprintf(stderr, "Error on Dynamic linking Filesystem : %s\n",
							val);
					err = true;
				}

				fs_ops = dlsym(dlhandle, "fsops");
				if(!fs_ops) {
					fprintf(stderr, "Error on Linking Filesystem Operations : %s\n",
							val);
					err = true;
				}
				
				if(!err) {
					fs_ops_dlhandle = dlhandle;
					fs_engine = FSENGINE_USER;
				}
			}
		}
		config_opt("format_required") {
			req_format = atoi(val);
		}
		config_opt("meta_ratio") {
			meta_ratio = atoi(val);
		}
		config_opt("wrap_dir") {
			setup_io_dir(val);
		}
	}

	fclose(fp);

	if(storage_engine == IOENGINE_NONE) {
		setup_io_engine_linux();
		storage_engine = IOENGINE_LINUX;
		fprintf(stderr, "Unknown storage engine, Using defaut I/O engine - LINUX\n");
	}

	if(fs_engine == FSENGINE_NONE) {
		setup_io_engine_linux();
		fs_engine = FSENGINE_LINUX;
		fprintf(stderr, "Unknown filesystem, Using defaut filesystem\n");
	}

	return;
}

void setup_fd_table(void) {
	struct rlimit val;

	if(getrlimit(RLIMIT_NOFILE, &val) < 0) {
		fprintf(stderr, "Error on get RLIMIT_NOFILE\n");
		return;
	}

	USR_FD_START = val.rlim_max + 1;
	nr_dirp_list = val.rlim_max;
}

static void init_io_constructor(void) {
	char* config_path;
	struct io_init_opt io_opt;
	//struct fs_init_opt fs_opt;

	fs_ops = NULL;
	io_ops = NULL;

	setup_fd_table();

	dirp_list = calloc(nr_dirp_list, sizeof(DIR*));
	pthread_spin_init(&dirp_list_lock, 0);

	setup_io_engine_linux();

	config_path = getenv("NVMED_WRAP_CONFIG");
	if(config_path != NULL) {
		wrapper_config(config_path);
	}
	else {
		wrapper_config("./default.conf");
	}
	if(io_ops && io_ops->init) {
		io_opt.path = USR_ABS_DIR;

		io_ops->init(&io_opt);
	}
/*
	if(req_format && fs_ops->format) {
		fs_opt.path = USR_ABS_DIR;
		fs_opt.dev_path = storage_dev;
		fs_opt.io_ops = io_ops;
		fs_opt.meta_ratio = meta_ratio;

		fs_ops->format(&fs_opt);
	}
	if(fs_ops->init) {
		fs_opt.path = USR_ABS_DIR;
		fs_opt.dev_path = storage_dev;
		fs_opt.io_ops = io_ops;
		fs_ops->init(&fs_opt);
	}
*/
}

static void final_io_destructor(void) {
	if(fs_ops->finalize) {
		fs_ops->finalize();
	}

	if(fs_engine == FSENGINE_USER)
		dlclose(fs_ops_dlhandle);

	//if(storage_engine == IOENGINE_USER)
	//	dlclose(io_ops_dlhandle);

	pthread_spin_destroy(&dirp_list_lock);
	free(USR_ABS_DIR);

	free(USR_DIR_PARENT);
}


// todo -------------------------------

// openat
// getdents
// getdents64

// getcwd
// readv
// writev
// pipe
// select
// dup
// dup2
// sendfile


// chdir
// fchdir
// creat
// link
// unlink
// symlink
// readlink
// chmod
// fchmod
// chown
// fchown
// lchown
// utime
// mknod
// ustat
// statfs
// fstatfs
// chroot
// setxattr
// lsetxattr
// fsetxattr
// getxattr
// lgetxattr
// fgetxattr
// listxattr
// llistxattr
// flistxattr
// removexattr
// lremovexattre
// fremovexattr
// io_setup
// io_destroy
// io_getevents
// io_submit
// io_cancel
// utimes
// mkdirat
// mknodat
// fchownat
// futimesat
// newfstatat
// unlinkat
// renameat
// linkat
// symlinkat
// readlinkat
// fchmodat
// faccessat
// sync_file_range
