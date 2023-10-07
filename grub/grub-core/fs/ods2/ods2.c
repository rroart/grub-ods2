/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999, 2001, 2003  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define FSYS_ODS2
#ifdef FSYS_ODS2

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/fshelp.h>
#include <grub/safemath.h>
#include <grub/gui_string_util.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_dl_t my_mod;

#include "mytypes.h"
#include "fiddef.h"
#include "uicdef.h"
#include "fatdef.h"
#include "dirdef.h"
#include "fh2def.h"
#include "fm2def.h"
#include "hm2def.h"

#define BLOCKSIZE 512
#define MAXREC (BLOCKSIZE - 2)

#if 0
#define STRUCT_DIR_SIZE (sizeof(struct _dir)) // but this gives one too much
#else
#define STRUCT_DIR_SIZE 7 
#endif

/* sizes are always in bytes, BLOCK values are always in DEV_BSIZE (sectors) */
#define DEV_BSIZE 512

/* include/linux/fs.h */
#define BLOCK_SIZE 512		/* initial block size for superblock read */
/* made up, defaults to 1 but can be passed via mount_opts */
#define HOME_BLOCK 1

#define _home_block(FSYS_BUF) ((struct _hm2 *)(FSYS_BUF))
#define _index_header(FSYS_BUF) ((struct _fh2 *)((long) FSYS_BUF + 0x200))
#define _mfd_header(FSYS_BUF) ((struct _fh2 *)((long) FSYS_BUF + 0x400))
#define _mfd(FSYS_BUF) ((struct _fh2 *)((long) FSYS_BUF + 0x600))
#define _file_header(FSYS_BUF) ((struct _fh2 *)((long) FSYS_BUF + 0x800))
#define _dir(FSYS_BUF) ((struct _dir *)((long) FSYS_BUF + 0xa00))

int mymemcmp(char * s, char * t, int size);
struct grub_ods2_data * grub_ods2_mount(grub_disk_t disk);
int ods2_read_old (char *buf, int len, grub_disk_t disk, void * data, int filepos);
static int ods2_index_block_map (unsigned int logical_block, void * data);
static int ods2_block_map (unsigned int logical_block, void * data);
int get_fm2_val(unsigned short ** mpp, unsigned int * phyblk, unsigned int *phylen);
grub_err_t grub_ods2_dir_old (grub_device_t device, const char *path, grub_fs_dir_hook_t hook, void *hook_data);

struct grub_fshelp_node
{
  struct grub_ods2_data *data;
  struct _fh2 inode;
  int ino;
  int inode_read;
};

/* Information about a "mounted" ods2 filesystem.  */
struct grub_ods2_data
{
  struct _hm2 sblock;
  int log_group_desc_size;
  grub_disk_t disk;
  struct _fh2 *inode;
  struct grub_fshelp_node diropen;
  void * fsys_buf;
};

/* Context for grub_ods2_dir.  */
struct grub_ods2_dir_ctx
{
  grub_fs_dir_hook_t hook;
  void *hook_data;
  struct grub_ods2_data *data;
};

int mymemcmp(char * s, char * t, int size) {
  for (;size;size--,s++,t++)
    if ((*s)!=(*t)) return 1;
  return 0;
}

/* Read the inode INO for the file described by DATA into INODE.  */
static grub_err_t
grub_ods2_read_inode (struct grub_ods2_data *data,
		      int ino, struct _fh2 *inode)
{
  /* Read the inode.  */

  ods2_read_old((void *) inode, sizeof(struct _fh2), data -> disk, data->fsys_buf, ino);
  
  return 0;
}

struct grub_ods2_data *
grub_ods2_mount (grub_disk_t disk)
{
  struct grub_ods2_data * data = grub_malloc(sizeof (struct grub_ods2_data));
  void * fsys_buf = grub_malloc (6 * 512);
  if (!data || ! fsys_buf)
    return 0;

  data -> fsys_buf = fsys_buf;

  struct _hm2 * home_block = _home_block(data->fsys_buf);

  grub_disk_read(disk, HOME_BLOCK, 0, 512, home_block);

  if (mymemcmp(home_block->hm2$t_format, (char *) "DECFILE11B  ", 12) != 0)
      return 0;

  grub_disk_read(disk, VMSLONG(home_block->hm2$l_ibmaplbn) + VMSWORD(home_block->hm2$w_ibmapsize), 0, 512, _index_header(data->fsys_buf));

  grub_disk_read(disk, VMSLONG(home_block->hm2$l_ibmaplbn) + VMSWORD(home_block->hm2$w_ibmapsize) + (4 - 1), 0, 512, _mfd_header(data->fsys_buf));

  grub_disk_read(disk, VMSLONG(home_block->hm2$l_ibmaplbn) + VMSWORD(home_block->hm2$w_ibmapsize) + (4 - 1), 0, 512, _file_header(data->fsys_buf));

  ods2_read_old((void *) _mfd(data->fsys_buf), 512, disk, data->fsys_buf, 0);

  return data;
}

static int
grub_ods2_iterate_dir (grub_fshelp_node_t dir,
		       grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
  //unsigned int fpos = 0;
  struct grub_fshelp_node *diro = (struct grub_fshelp_node *) dir;

  if (! diro->inode_read)
    {
      grub_ods2_read_inode (diro->data, diro->ino, &diro->inode);
      if (grub_errno)
	return 0;
    }

  /* Search the file.  */

  void * data = 0; // TODO
  struct _dir * dr = (void *) _mfd(data);
  
  while (1) {
    //char * rest, ch;
    // int str_chk;

    struct _fh2 * file_header = _file_header(data);
    if ((VMSLONG(file_header->fh2$l_filechar) & FH2$M_DIRECTORY)==0)
      {
	grub_errno = GRUB_ERR_BAD_FILE_TYPE;
	return 0;
      }

    /* skip to next slash or end of filename (space) */
    /*
    for (rest = (char *) path; (ch = *rest) && !grub_isspace (ch) && ch != '/';
	 rest++);

    *rest = 0;
    */
    
    do {

      if (VMSWORD(dr->dir$w_size) > MAXREC)
	{
	  //grub_printf("dr %x %x %x %x\n",dr,dr->dir$w_size,dr->dir$w_verlimit,dr->dir$b_namecount); 
	  return 1;
	}


    struct _dir1 *de = (void *)((char *) dr-sizeof(struct _dir1)); //(struct _dir1 *) (dr->dir$t_name + ((dr->dir$b_namecount + 1) & ~1));
    struct _fiddef * fid = &de->dir$fid;
    int filenum = fid->fid$w_num + (fid->fid$b_nmx<<16);
    struct _hm2 * home_block = _home_block(data);
    int phy = ods2_index_block_map(VMSLONG(home_block->hm2$w_ibmapvbn) + VMSWORD(home_block->hm2$w_ibmapsize) + filenum - 1, data);
    //grub_printf("filen %x %x %x %x %x\n",filenum,fid->fid$w_num,fid->fid$b_nmx,fid->fid$w_seq,phy);
    grub_disk_t disk = diro->data->disk;
    grub_disk_read(disk, phy, 0, 512, file_header);
    //grub_disk_read(disk, VMSLONG(home_block->hm2$l_ibmaplbn) + VMSWORD(home_block->hm2$w_ibmapsize) + (filenum - 1), 0, 512, file_header);
    // TODO filepos = 0;
    //ods2_read_old((char *) path, 512, disk, data, 0);
    // TODO filepos = 0;
    //dr = (void *) path;



      enum grub_fshelp_filetype type = GRUB_FSHELP_UNKNOWN;
      

      
      //int saved_c = dr->dir$t_name[dr->dir$b_namecount];
      //dr->dir$t_name[dr->dir$b_namecount]=0;
      void * filename = grub_new_substring(dr->dir$t_name, 0, dr->dir$b_namecount);
      //dr->dir$t_name[dr->dir$b_namecount]=saved_c;


      struct grub_fshelp_node *fdiro;
      	  fdiro = grub_malloc (sizeof (struct grub_fshelp_node));
	  if (! fdiro)
	    return 0;

	  fdiro->data = diro->data;
	  fdiro->ino = grub_le_to_cpu32(filenum);

	  //filename[dirent.namelen] = '\0';

	  
	      fdiro->inode_read = 0;

	      if ((VMSLONG(file_header->fh2$l_filechar) & FH2$M_DIRECTORY)==0)
		type = GRUB_FSHELP_REG;
	      else
		type = GRUB_FSHELP_DIR;

	      if (hook (filename, type, fdiro, hook_data))
	    return 1;


      
      dr = (void *) ((char *) dr + VMSWORD(dr->dir$w_size) + 2);      
    } while (VMSWORD(dr->dir$w_size) < MAXREC);

    // TODO *(path = (void *) rest) = ch;
    }

  return 0;
  }

int
get_fm2_val(unsigned short ** mpp, unsigned int * phyblk, unsigned int *phylen) {
  unsigned short *mp=*mpp;
  if (phyblk==0 || phylen==0) return -1;
	switch (VMSWORD(*mp) >> 14) {
	case FM2$C_PLACEMENT:
	  *phylen = 0;
	  (*mpp)++;
	  break;
	case FM2$C_FORMAT1:
	  *phylen = (VMSWORD(*mp) & 0377) + 1;
	  *phyblk = ((VMSWORD(*mp) & 037400) << 8) | VMSWORD(mp[1]);
	  (*mpp) += 2;
	  break;
	case FM2$C_FORMAT2:
	  *phylen = (VMSWORD(*mp) & 037777) + 1;
	  *phyblk = (VMSWORD(mp[2]) << 16) | VMSWORD(mp[1]);
	  (*mpp) += 3;
	  break;
	case FM2$C_FORMAT3:
	  *phylen = ((VMSWORD(*mp) & 037777) << 16) + VMSWORD(mp[1]) + 1;
	  *phyblk = (VMSWORD(mp[3]) << 16) | VMSWORD(mp[2]);
	  (*mpp) += 4;
	  break;
	default:
	  return 0;
	}
	return 1;
}

static int
ods2_index_block_map (unsigned int logical_block, void * data)
{
  unsigned int curvbn=1; // should be 1, but I guess grub starts at 0
  unsigned short *me;
  struct _fh2 * index_header = _index_header(data);
  unsigned short *mp = (unsigned short *) index_header + index_header->fh2$b_mpoffset;
  me = mp + index_header->fh2$b_map_inuse;

  while (mp < me) {
    unsigned int phyblk, phylen;
    get_fm2_val(&mp,&phyblk,&phylen);
    //grub_printf("get %x %x %x %x %x %x",mp,phyblk,phylen,curvbn,logical_block,index_header->fh2$b_map_inuse);
    if (logical_block>=curvbn && logical_block<(curvbn+phylen))
      return phyblk+logical_block-curvbn;
    if (phylen!=0) {
      curvbn += phylen;
    }
  }
  return -1;
}

static int
ods2_block_map (unsigned int logical_block, void * data)
{
  unsigned int curvbn=0; // should be 1, but I guess grub starts at 0
  unsigned short *me;
  struct _fh2 * file_header = _file_header(data);
  unsigned short *mp = (unsigned short *) file_header + file_header->fh2$b_mpoffset;
  me = mp + file_header->fh2$b_map_inuse;

  while (mp < me) {
    unsigned int phyblk, phylen;
    get_fm2_val(&mp,&phyblk,&phylen);
    //    grub_printf("get %x %x %x %x %x %x",mp,phyblk,phylen,curvbn,logical_block,file_header->fh2$b_map_inuse);
    if (logical_block>=curvbn && logical_block<(curvbn+phylen))
      return phyblk+logical_block-curvbn;
    if (phylen!=0) {
      curvbn += phylen;
    }
  }
  return -1;
}

/* Read LEN bytes from the file described by DATA starting with byte
   POS.  Return the amount of read bytes in READ.  */
static grub_ssize_t
grub_ods2_read_file (grub_fshelp_node_t node,
		     grub_disk_read_hook_t read_hook, void *read_hook_data,
		     grub_off_t pos, grub_size_t len, char *buf)
{
  //ub_printf("%lx %lx %lx %lx, %lx %s", (long) &node, (long) &read_hook, (long) read_hook_data, (long) &pos, (long) &len, buf);
  return grub_fshelp_read_file (node->data->disk, node,
				read_hook, read_hook_data,
				pos, len, buf, grub_ods2_read_block,
				(grub_off_t) len,
				9, 0);
}


/* Open a file named NAME and initialize FILE.  */
static grub_err_t
grub_ods2_open (struct grub_file *file, const char *name)
{
  struct grub_ods2_data *data;
  struct grub_fshelp_node *fdiro = 0;
  grub_err_t err;

  grub_dl_ref (my_mod);

  data = grub_ods2_mount (file->device->disk);
  if (! data)
    {
      err = grub_errno;
      goto fail;
    }

  err = grub_fshelp_find_file (name, &data->diropen, &fdiro,
			       grub_ods2_iterate_dir,
			       0, GRUB_FSHELP_REG);
  if (err)
    goto fail;

  if (! fdiro->inode_read)
    {
      err = grub_ods2_read_inode (data, fdiro->ino, &fdiro->inode);
      if (err)
	goto fail;
    }

  grub_memcpy (data->inode, &fdiro->inode, sizeof (struct _fh2));
  grub_free (fdiro);

  struct _fh2 * file_header = 0; // TODO
  struct _fatdef * fat = &file_header->fh2$w_recattr;
  int filemax = (VMSSWAP(fat->fat$l_efblk)<<9)-512+fat->fat$w_ffbyte;

  file->size = grub_le_to_cpu32 (filemax);
  file->size |= ((grub_off_t) grub_le_to_cpu32 (data->inode->size_high)) << 32;
  file->data = data;
  file->offset = 0;

  return 0;

 fail:
  if (fdiro != &data->diropen)
    grub_free (fdiro);
  grub_free (data);

  grub_dl_unref (my_mod);

  return err;
}

static grub_err_t
grub_ods2_close (grub_file_t file)
{
  grub_free (file->data);

  grub_dl_unref (my_mod);

  return GRUB_ERR_NONE;
}

int
ods2_read_old (char *buf, int len, grub_disk_t disk, void * data, int filepos)
{
  int logical_block;
  int offset;
  int map;
  int ret = 0;
  int size = 0;

  while (len > 0)
    {
      /* find the (logical) block component of our location */
      logical_block = filepos >> 9;
      offset = filepos & (512 - 1);
      map = ods2_block_map (logical_block, data);
      if (map < 0)
	break;

      size = 512;
      size -= offset;
      if (size > len)
	size = len;

      grub_disk_read(disk, map, offset, size, buf);

      buf += size;
      len -= size;
      filepos += size;
      ret += size;
    }

  if (grub_errno) // TODO
    ret = 0;

  return ret;
}

/* Read LEN bytes data from FILE into BUF.  */
static grub_ssize_t
grub_ods2_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_ods2_data *data = (struct grub_ods2_data *) file->data;
  grub_printf("%lx %lx %lx", (long) data, (long) buf, (long) &len);
  return grub_ods2_read_file (&data->diropen,
			      file->read_hook, file->read_hook_data,
			      file->offset, len, buf);
}


/* Helper for grub_ods2_dir.  */
static int
grub_ods2_dir_iter (const char *filename, enum grub_fshelp_filetype filetype,
		    grub_fshelp_node_t node, void *data)
{
  struct grub_ods2_dir_ctx *ctx = data;
  struct grub_dirhook_info info;

  grub_memset (&info, 0, sizeof (info));
  if (! node->inode_read)
    {
      grub_ods2_read_inode (ctx->data, node->ino, &node->inode);
      if (!grub_errno)
	node->inode_read = 1;
      grub_errno = GRUB_ERR_NONE;
    }
  if (node->inode_read)
    {
      info.mtimeset = 1;
      // TODO info.mtime = grub_le_to_cpu32 (node->inode.mtime);
    }

  info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
  grub_free (node);
  return ctx->hook (filename, &info, ctx->hook_data);
}

static grub_err_t
grub_ods2_dir (grub_device_t device, const char *path, grub_fs_dir_hook_t hook,
	       void *hook_data)
{
  struct grub_ods2_dir_ctx ctx = {
    .hook = hook,
    .hook_data = hook_data
  };
  struct grub_fshelp_node *fdiro = 0;

  grub_dl_ref (my_mod);

  ctx.data = grub_ods2_mount (device->disk);
  if (! ctx.data)
    goto fail;

  grub_fshelp_find_file (path, &ctx.data->diropen, &fdiro,
			 grub_ods2_iterate_dir, 0,
			 GRUB_FSHELP_DIR);
  if (grub_errno)
    goto fail;

  grub_ods2_iterate_dir (fdiro, grub_ods2_dir_iter, &ctx);

 fail:
  if (fdiro != &ctx.data->diropen)
    grub_free (fdiro);
  grub_free (ctx.data);

  grub_dl_unref (my_mod);

  return grub_errno;
}

grub_err_t
grub_ods2_dir_old (grub_device_t device, const char *path, grub_fs_dir_hook_t hook,
	       void *hook_data)
{
  grub_printf("%lx %lx\n", (long) &hook, (long) hook_data);
  //grub_printf("dir X%sX\n",path);
  void * data = 0; // TODO
  struct _dir * dr = (void *) _mfd(data);
  
  while (1) {
    char * rest, ch;
    // int str_chk;

    if (!*path || grub_isspace (*path))
      {
	//struct _fiddef * fid = &file_header->fh2$w_fid;
	//grub_printf("fid %x %x %x\n",fid->fid$w_num,fid->fid$b_nmx,fid->fid$w_seq);
	//struct _fh2 * file_header = _file_header(data);
	//struct _fatdef * fat = &file_header->fh2$w_recattr;
	// int filemax = (VMSSWAP(fat->fat$l_efblk)<<9)-512+fat->fat$w_ffbyte;
	//grub_printf("filemax %x\n",filemax);
	return 1;
      }

    while (*path == '/')
      path++;

    struct _fh2 * file_header = _file_header(data);
    if ((VMSLONG(file_header->fh2$l_filechar) & FH2$M_DIRECTORY)==0)
      {
	grub_errno = GRUB_ERR_BAD_FILE_TYPE;
	return 0;
      }

    /* skip to next slash or end of filename (space) */
    for (rest = (char *) path; (ch = *rest) && !grub_isspace (ch) && ch != '/';
	 rest++);

    *rest = 0;

    // TODO
    /*
    do {

      if (VMSWORD(dr->dir$w_size) > MAXREC)
	{
	  //grub_printf("dr %x %x %x %x\n",dr,dr->dir$w_size,dr->dir$w_verlimit,dr->dir$b_namecount); 
	  if (print_possibilities < 0)
	    {
	    }
	  else
	    {
	      grub_errno = GRUB_ERR_FILE_NOT_FOUND;
	      *rest = ch;
	    }
	  return (print_possibilities < 0);
	}

      int saved_c = dr->dir$t_name[dr->dir$b_namecount];
      dr->dir$t_name[dr->dir$b_namecount]=0;
      str_chk = substring(path,dr->dir$t_name);

      #if 0
# ifndef STAGE1_5
      if (print_possibilities && ch != '/'
	  && (!*path || str_chk <= 0))
	{
	  if (print_possibilities > 0)
	    print_possibilities = -print_possibilities;
	  print_a_completion (dr->dir$t_name);
	}
# endif
      #endif

      dr->dir$t_name[dr->dir$b_namecount]=saved_c;

      dr = (void *) ((char *) dr + VMSWORD(dr->dir$w_size) + 2);      
    */
    //    } while (/*!dp->inode ||*/ (str_chk || (print_possibilities && ch != '/')));
    struct _dir1 *de = (void *)((char *) dr-sizeof(struct _dir1)); //(struct _dir1 *) (dr->dir$t_name + ((dr->dir$b_namecount + 1) & ~1));
    struct _fiddef * fid = &de->dir$fid;
    int filenum = fid->fid$w_num + (fid->fid$b_nmx<<16);
    struct _hm2 * home_block = _home_block(data);
    int phy = ods2_index_block_map(VMSLONG(home_block->hm2$w_ibmapvbn) + VMSWORD(home_block->hm2$w_ibmapsize) + filenum - 1, data);
    //grub_printf("filen %x %x %x %x %x\n",filenum,fid->fid$w_num,fid->fid$b_nmx,fid->fid$w_seq,phy);
    grub_disk_t disk = device->disk;
    grub_disk_read(disk, phy, 0, 512, file_header);
    //grub_disk_read(disk, VMSLONG(home_block->hm2$l_ibmaplbn) + VMSWORD(home_block->hm2$w_ibmapsize) + (filenum - 1), 0, 512, file_header);
    // TODO filepos = 0;
    ods2_read_old((char *) path, 512, disk, data, 0);
    // TODO filepos = 0;
    dr = (void *) path;
    // TODO *(path = (void *) rest) = ch;
  }
}

static grub_err_t
grub_ods2_label (grub_device_t device, char **label)
{
  void *data;
  grub_disk_t disk = device->disk;

  grub_dl_ref (my_mod);

  data = grub_ods2_mount (disk);

  struct _hm2 * home_block = _home_block(data);

  if (data)
    *label = grub_strndup (home_block->hm2$t_volname,
			   sizeof (home_block->hm2$t_volname));
  else
    *label = NULL;

  grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;
}

static grub_err_t
grub_ods2_uuid (__attribute__ ((unused)) grub_device_t device, char **uuid)
{
  // TODO serialnum
  *uuid = NULL;

  return grub_errno;
}

/* Get mtime.  */
static grub_err_t
grub_ods2_mtime (__attribute__ ((unused)) grub_device_t device, grub_int64_t *tm)
{

  *tm = 0;

  return grub_errno;
}

static struct grub_fs grub_ods2_fs =
  {
    .name = "ods2",
    .fs_dir = grub_ods2_dir,
    .fs_open = grub_ods2_open,
    .fs_read = grub_ods2_read,
    .fs_close = grub_ods2_close,
    .fs_label = grub_ods2_label,
    .fs_uuid = grub_ods2_uuid,
    .fs_mtime = grub_ods2_mtime,
#ifdef GRUB_UTIL
    .reserved_first_sector = 1,
    .blocklist_install = 1,
#endif
    .next = 0
  };

GRUB_MOD_INIT(ods2)
{
  grub_fs_register (&grub_ods2_fs);
  my_mod = mod;
}

GRUB_MOD_FINI(ods2)
{
  grub_fs_unregister (&grub_ods2_fs);
}

#endif /* FSYS_ODS2 */