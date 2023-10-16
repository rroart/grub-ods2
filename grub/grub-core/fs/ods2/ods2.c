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

//#define _home_block(FSYS_BUF) ((struct _hm2 *)(FSYS_BUF))
//#define _index_header(FSYS_BUF) ((struct _fh2 *)((long) FSYS_BUF + 0x200))
//#define _mfd_header(FSYS_BUF) ((struct _fh2 *)((long) FSYS_BUF + 0x400))
//#define _mfd(FSYS_BUF) ((struct _fh2 *)((long) FSYS_BUF + 0x600))
//#define _file_header(FSYS_BUF) ((struct _fh2 *)((long) FSYS_BUF + 0x800))
//#define _dir(FSYS_BUF) ((struct _dir *)((long) FSYS_BUF + 0xa00))

int mymemcmp(char * s, char * t, int size);
struct grub_ods2_data * grub_ods2_mount(grub_disk_t disk);
int ods2_read_old (char *buf, int len, grub_disk_t disk, struct grub_ods2_data * data, int filepos);
static int ods2_index_block_map (unsigned int logical_block, struct grub_ods2_data * data);
static int ods2_block_map (unsigned int logical_block, struct grub_ods2_data * data);
int get_fm2_val(unsigned short ** mpp, unsigned int * phyblk, unsigned int *phylen);
char * grub_my_new_substring (const char *buf, grub_size_t start, grub_size_t end);
void printbuf(const void * buf, const int len);
void printbuf16(const void * buf);
void printbuf32(const void * buf);
void printbuf36(const void * buf);
void printbuf48(const void * buf);

void printbuf(const void * buf, const int len) {
  for (int i = 0; i < len; i++) {
      grub_dprintf("ods", "%x ", *((char *) buf) + i);
  }
}

void printbuf16(const void * buf) {
  const unsigned char * c = buf;
  grub_dprintf("ods", "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x ", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]);
}

void printbuf32(const void * buf) {
  const unsigned char * c = buf;
  grub_dprintf("ods", "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x ", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15], c[16], c[17], c[18], c[19], c[20], c[21], c[22], c[23], c[24], c[25], c[26], c[27], c[28], c[29], c[30], c[31]);
}

void printbuf36(const void * buf) {
  const unsigned char * c = buf;
  grub_dprintf("ods", "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15], c[16], c[17], c[18], c[19], c[20], c[21], c[22], c[23], c[24], c[25], c[26], c[27], c[28], c[29], c[30], c[31], c[32], c[33], c[34], c[35]);
}

void printbuf48(const void * buf) {
  const unsigned char * c = buf;
  grub_dprintf("ods", "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x ", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15], c[16], c[17], c[18], c[19], c[20], c[21], c[22], c[23], c[24], c[25], c[26], c[27], c[28], c[29], c[30], c[31], c[32], c[33], c[34], c[35], c[36], c[37], c[38], c[39], c[40], c[41], c[42], c[43], c[44], c[45], c[46], c[47]);
}

struct grub_fshelp_node
{
  struct grub_ods2_data *data;
  struct _fh2 file_header;
  int filenum;
  int file_header_read;
};

/* Information about a "mounted" ods2 filesystem.  */
struct grub_ods2_data
{
  struct _hm2 home_block;
  struct _fh2 index_header;
  struct _fh2 mfd_header;
  char mfd[512];
  struct _fh2 dir;
  grub_disk_t disk;
  struct _fh2 *file_header;
  struct grub_fshelp_node diropen;
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

/*
void *
addme(void * addr, short offset) {
  return (unsigned short *) addr + offset;
}
 */

/* Create a new NUL-terminated string on the heap as a substring of BUF.
   The range of buf included is the half-open interval [START,END).
   The index START is inclusive, END is exclusive.  */
char *
grub_my_new_substring (const char *buf,
		       grub_size_t start, grub_size_t end)
{
  if (end < start)
    return 0;
  grub_size_t len = end - start;
  char *s = grub_malloc (len + 1);
  if (! s)
    return 0;
  grub_memcpy (s, buf + start, len);
  s[len] = '\0';
  return s;
}

/* Read the file_header INO for the file described by DATA into FILE_HEADER.  */
static grub_err_t
grub_ods2_read_file_header (struct grub_ods2_data *data,
			    int filenum, struct _fh2 *file_header)
{
  /* Read the file_header.  */

  struct _hm2 * home_block = &data->home_block;
  int phy = ods2_index_block_map(VMSLONG(home_block->hm2$w_ibmapvbn) + VMSWORD(home_block->hm2$w_ibmapsize) + filenum - 1, data);
  //grub_printf("filen %x %x %x %x %x\n",filenum,fid->fid$w_num,fid->fid$b_nmx,fid->fid$w_seq,phy);
  grub_disk_t disk = data->disk;
  grub_disk_read(disk, phy, 0, 512, file_header);
  //ods2_read_old((void *) file_header, sizeof(struct _fh2), data -> disk, data, filenum);
  //printbuf16(file_header);

  return 0;
}

struct grub_ods2_data *
grub_ods2_mount (grub_disk_t disk)
{
  struct grub_ods2_data * data = grub_malloc(sizeof (struct grub_ods2_data));
  if (!data)
    return 0;

  struct _hm2 * home_block = &data->home_block;

  grub_disk_read(disk, HOME_BLOCK, 0, 512, home_block);

  //grub_dprintf("ods", "hm %s", home_block->hm2$t_format);
  if (mymemcmp(home_block->hm2$t_format, (char *) "DECFILE11B  ", 12) != 0) {
    grub_error (GRUB_ERR_BAD_FS, "not an ODS2 filesystem");
    return 0;
  }
  //grub_dprintf("ods", "hm %s", home_block->hm2$t_format);

  grub_disk_read(disk, VMSLONG(home_block->hm2$l_ibmaplbn) + VMSWORD(home_block->hm2$w_ibmapsize), 0, 512, &data->index_header);

  grub_disk_read(disk, VMSLONG(home_block->hm2$l_ibmaplbn) + VMSWORD(home_block->hm2$w_ibmapsize) + (4 - 1), 0, 512, &data->mfd_header);

  //grub_dprintf("ods", "d %lx", (long unsigned int) data);
  //printbuf16(&data->mfd_header);

  data->disk = disk;
  data->diropen.data = data;
  data->diropen.filenum = 4;
  data->diropen.file_header_read = 1;
  data->file_header = &data->diropen.file_header;

  grub_disk_read(disk, VMSLONG(home_block->hm2$l_ibmaplbn) + VMSWORD(home_block->hm2$w_ibmapsize) + (4 - 1), 0, 512, data->file_header);
  //printbuf16(&data->file_header);

  ods2_read_old((void *) &data->mfd, 512, disk, data, 0);

  //printbuf16(data->mfd);
  //printbuf16(&data->mfd);

  return data;
}

static int
grub_ods2_iterate_dir (grub_fshelp_node_t dir,
		       grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
  //unsigned int fpos = 0;
  struct grub_fshelp_node *diro = (struct grub_fshelp_node *) dir;

  if (! diro->file_header_read)
    {
      grub_ods2_read_file_header (diro->data, diro->filenum, &diro->file_header);
      if (grub_errno)
	  return 0;
    }

  /* Search the file.  */

  //grub_dprintf("ods", "d %lx %lx", (long unsigned int) diro, (long unsigned int) diro->data);
  struct grub_ods2_data * data = diro->data;
  //printbuf16(data->mfd);
  //printbuf16(&data->mfd);
  struct _dir * dr = (void *) &data->mfd;

  while (1) {
      //char * rest, ch;
      // int str_chk;

      struct _fh2 * file_header = &data->mfd_header;
      //grub_dprintf("ods", "f %x %x %x", file_header->fh2$l_filechar, file_header->fh2$w_fid.fid$w_num, file_header->fh2$w_fid.fid$w_seq);
      if ((VMSLONG(file_header->fh2$l_filechar) & FH2$M_DIRECTORY)==0)
	{
	  grub_errno = GRUB_ERR_BAD_FILE_TYPE;
	  //printbuf16(file_header);
	  //grub_dprintf("ods", "BAD");
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
	      //grub_dprintf("ods", "MAX");
	      return 1;
	    }


	  struct _dir1 *de = (struct _dir1 *) (&dr->dir$t_name + ((dr->dir$b_namecount + 1) & ~1));
	  //struct _fiddef * fid = &de->dir$fid;
	  int filenum = de->dir$fid.fid$w_num + (de->dir$fid.fid$b_nmx<<16);
	  struct _hm2 * home_block = &data->home_block;
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
	  void * filename = grub_my_new_substring(dr->dir$t_name, 0, dr->dir$b_namecount);
	  //dr->dir$t_name[dr->dir$b_namecount]=saved_c;
	  //grub_dprintf("ods", "FN %s FN", (char *) filename);


	  struct grub_fshelp_node *fdiro;
	  fdiro = grub_malloc (sizeof (struct grub_fshelp_node));
	  if (! fdiro)
	    return 0;

	  fdiro->data = diro->data;
	  fdiro->filenum = grub_le_to_cpu32(filenum);

	  //filename[dirent.namelen] = '\0';


	  fdiro->file_header_read = 0;

	  if ((VMSLONG(fdiro->file_header.fh2$l_filechar) & FH2$M_DIRECTORY)==0)
	    type = GRUB_FSHELP_REG;
	  else
	    type = GRUB_FSHELP_DIR;

	  if (hook (filename, type, fdiro, hook_data))
	    return 1;



	  dr = (void *) ((char *) dr + VMSWORD(dr->dir$w_size) + 2);
	  //void * filename2 = grub_my_new_substring(dr->dir$t_name, 0, dr->dir$b_namecount);
	  //grub_dprintf("ods", "FN %s FN", (char *) filename2);
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
ods2_index_block_map (unsigned int logical_block, struct grub_ods2_data * data)
{
  unsigned int curvbn=1; // should be 1, but I guess grub starts at 0
  unsigned short *me;
  struct _fh2 * index_header = &data->index_header;
  //struct _fh2 index_header [] = &data->index_header;
  unsigned short * mp = (unsigned short *) index_header + index_header->fh2$b_mpoffset;
  //unsigned short * mp = addme((void *) index_header, index_header->fh2$b_mpoffset);
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
ods2_block_map (unsigned int logical_block, struct grub_ods2_data * data)
{
  unsigned int curvbn=0; // should be 1, but I guess grub starts at 0
  unsigned short *me;
  struct _fh2 * file_header = data->file_header;
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

static grub_disk_addr_t
grub_ods2_read_block (grub_fshelp_node_t node, grub_disk_addr_t fileblock)
{
  struct grub_ods2_data *data = node->data;
  //struct _fh2 *file_header = &node->file_header;
  int map = ods2_block_map (fileblock, data);
  return map;
}

/* Read LEN bytes from the file described by DATA starting with byte
   POS.  Return the amount of read bytes in READ.  */
static grub_ssize_t
grub_ods2_read_file (grub_fshelp_node_t node,
		     grub_disk_read_hook_t read_hook, void *read_hook_data,
		     grub_off_t pos, grub_size_t len, char *buf)
{
  //ub_printf("%lx %lx %lx %lx, %lx %s", (long) &node, (long) &read_hook, (long) read_hook_data, (long) &pos, (long) &len, buf);
  grub_off_t size = (VMSSWAP(node->file_header.fh2$w_recattr.fat$l_efblk)<<9)-512+node->file_header.fh2$w_recattr.fat$w_ffbyte;

  return grub_fshelp_read_file (node->data->disk, node,
				read_hook, read_hook_data,
				pos, len, buf, grub_ods2_read_block,
				size,
				0, 0);
}


/* Open a file named NAME and initialize FILE.  */
static grub_err_t
grub_ods2_open (struct grub_file *file, const char *name)
{
  //grub_dprintf("ods", "f %s", name);
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

  if (! fdiro->file_header_read)
    {
      err = grub_ods2_read_file_header (data, fdiro->filenum, &fdiro->file_header);
      if (err)
	goto fail;
    }

  grub_memcpy (data->file_header, &fdiro->file_header, sizeof (struct _fh2));
  grub_free (fdiro);

  struct _fh2 * file_header = data->file_header;
  //grub_dprintf("ods", "num %x", fdiro->filenum);
  //printbuf48(file_header);
  //struct _fatdef * fat = &file_header->fh2$w_recattr;
  int filemax = (VMSSWAP(file_header->fh2$w_recattr.fat$l_efblk)<<9)-512+file_header->fh2$w_recattr.fat$w_ffbyte;

  file->size = grub_le_to_cpu32 (filemax);
  //grub_dprintf("ods", "s %x %x %x", (unsigned int) file->size, (unsigned int) file_header->fh2$w_recattr.fat$l_efblk, (unsigned int) file_header->fh2$w_recattr.fat$w_ffbyte);
  //file->size |= ((grub_off_t) grub_le_to_cpu32 (data->file_header->size_high)) << 32;
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
ods2_read_old (char *buf, int len, grub_disk_t disk, struct grub_ods2_data * data, __attribute__ ((unused)) int fileposn)
{
  int logical_block;
  int offset;
  int map;
  int ret = 0;
  int size = 0;
  int filepos = 0;

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

      //grub_dprintf("ods", "old %x %x %x", (unsigned int) map, (unsigned int) offset, (unsigned int) size);
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
  //grub_dprintf("ods", "r %lx %lx %lx", (long) data, (long) buf, (long) len);
  return grub_ods2_read_file (&data->diropen,
			      file->read_hook, file->read_hook_data,
			      file->offset, len, buf);
}


/* Helper for grub_ods2_dir.  */
static int
grub_ods2_dir_iter (const char *filename, enum grub_fshelp_filetype filetype,
		    grub_fshelp_node_t node, void *data)
{
  //grub_dprintf("ods", "f %s", filename);
  struct grub_ods2_dir_ctx *ctx = data;
  struct grub_dirhook_info info;

  grub_memset (&info, 0, sizeof (info));
  if (! node->file_header_read)
    {
      //grub_dprintf("ods", "f %x", node->filenum);
      //grub_dprintf("ods", "e %x", grub_errno);
      grub_ods2_read_file_header (ctx->data, node->filenum, &node->file_header);
      if (!grub_errno)
	node->file_header_read = 1;
      grub_errno = GRUB_ERR_NONE;
    }
  if (node->file_header_read)
    {
      info.mtimeset = 1;
      // TODO info.mtime = grub_le_to_cpu32 (node->file_header.mtime);
    }

  info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
  grub_free (node);
  return ctx->hook (filename, &info, ctx->hook_data);
}

static grub_err_t
grub_ods2_dir (grub_device_t device, const char *path, grub_fs_dir_hook_t hook,
	       void *hook_data)
{
  //grub_dprintf("ods", "NOBAD %s", path);
  struct grub_ods2_dir_ctx ctx = {
      .hook = hook,
      .hook_data = hook_data
  };
  struct grub_fshelp_node *fdiro = 0;
  //grub_dprintf("ods", "d %lx", (long unsigned int) &fdiro);

  grub_dl_ref (my_mod);

  ctx.data = grub_ods2_mount (device->disk);
  if (! ctx.data)
    goto fail;

  grub_fshelp_find_file (path, &ctx.data->diropen, &fdiro,
			 grub_ods2_iterate_dir, 0,
			 GRUB_FSHELP_DIR);
  //grub_dprintf("ods", "NOBAD");
  if (grub_errno)
    goto fail;

  //grub_dprintf("ods", "NOBAD");
  grub_ods2_iterate_dir (fdiro, grub_ods2_dir_iter, &ctx);

  fail:
  if (fdiro != &ctx.data->diropen)
    grub_free (fdiro);
  grub_free (ctx.data);

  grub_dl_unref (my_mod);

  //grub_dprintf("ods", "BAD");
  //grub_errno = GRUB_ERR_BAD_FS;
  return grub_errno;
}

static grub_err_t
grub_ods2_label (grub_device_t device, char **label)
{
  struct grub_ods2_data *data;
  grub_disk_t disk = device->disk;

  grub_dl_ref (my_mod);

  data = grub_ods2_mount (disk);

  struct _hm2 * home_block = &data->home_block;

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
