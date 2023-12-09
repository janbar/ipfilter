/*
 *      Copyright (C) 2023 Jean-Luc Barriere
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "db.h"

#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define DBTAG_LEN 4
static const char * g_dbtag = "IPF3";
static const int g_indianness = 0xff000000;

#define SEGS 0x100      /* base of segment size */
#define LEAF 0x80000000 /* bit 31 */
#define ADDR 0x7fffffff /* bit 30-0 */

typedef struct
{
  char      tag[4];
  uint32_t  indianness;
  uint32_t  max_file_size;
  char      db_name[32];
  int64_t   created;
  int64_t   updated;

  uint16_t  seg_nb;         /* nb extents */
  uint16_t  seg_sz;         /* segment size */
  uint32_t  free_node;      /* front of freelist (node id) */
  uint32_t  root_node;      /* node id of the root */
} db_header;

typedef struct
{
  uint32_t  raw0;           /* 1 bit leaf, 31 bit addr */
  uint32_t  raw1;           /* 1 bit leaf, 31 bit addr */
} node;

typedef struct
{
  void *    addr;
  size_t    reserved_size;
  size_t    allocated_size;
  FILE *    file;
  int       flag_rw;
} mmap_ctx;

struct DB
{
  db_header * header;
  node *      data;
  void (*destructor)(DB*);
  mmap_ctx    mmap_ctx;

  struct
  {
    uint16_t seg_nb;
    uint16_t seg_sz;
  } cache;
};

typedef struct mounted mounted;

struct mounted
{
  DB *      db;
  uint32_t  hash;
  uint32_t  refcount;
  mounted * _prev;
  mounted * _next;
};

static mounted * g_mounted = NULL;

static uint32_t _hash(uint32_t maxsize, const char * buf, unsigned len)
{
  /*
   * DJB Hash Function
   */
  uint32_t h = 5381;
  const char * end = buf + len;

  while (buf < end)
  {
    h = ((h << 5) + h) + *buf++;
  }
  return h % maxsize;
}

static DB * _hold_mounted(const char * filepath)
{
  uint32_t h = _hash(0xffffffff, filepath, strlen(filepath));
  mounted * m = g_mounted;
  while (m)
  {
    if (m->hash == h)
    {
      ++(m->refcount);
      return m->db;
    }
    m = m->_next;
  }
  return NULL;
}

static void _register_mounted(const char * filepath, DB * db)
{
  mounted * m = (mounted*) malloc(sizeof(mounted));
  m->db = db;
  m->hash = _hash(0xffffffff, filepath, strlen(filepath));
  m->refcount = 1;
  m->_prev = NULL;
  m->_next = NULL;
  if (g_mounted)
  {
    m->_next = g_mounted;
    g_mounted->_prev = m;
  }
  g_mounted = m;
}

static int _release_mounted(DB * db)
{
  mounted * m = g_mounted;
  while (m)
  {
    if (m->db == db)
    {
      if (m->refcount > 1)
        return --(m->refcount);
      /* free */
      if (!m->_prev && !m->_next)
        g_mounted = NULL;
      else
      {
        if (m->_prev)
          m->_prev->_next = m->_next;
        if (m->_next)
          m->_next->_prev = m->_prev;
      }
      free(m);
      return 0; /* no more reference */
    }
    m = m->_next;
  }
  /* no reference */
  return 0;
}

static void * _mmap_reserve(uint32_t size)
{
  void * addr;
  addr = mmap(NULL, size, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  if (addr == MAP_FAILED)
    return NULL;
  return addr;
}

static int _mmap_database(mmap_ctx * ctx)
{
  void * addr;
  struct stat sb;
  int prot, fd;

  /* check context */
  if (!ctx->file || !ctx->addr)
    return -(EINVAL);
  /* stat for size to allocate */
  fd = fileno(ctx->file);
  if (fstat(fd, &sb) == -1)
    return -(EIO);
  /* check reserved address space */
  if (sb.st_size > (off_t) ctx->reserved_size)
    return -(ERANGE);

  prot = PROT_READ;
  if (ctx->flag_rw)
    prot |= PROT_WRITE;

  addr = mmap(ctx->addr, sb.st_size, prot, MAP_FIXED|MAP_SHARED, fd, 0);
  if (addr == MAP_FAILED)
    return -(ENOMEM);
  /* mmap succeeded */
  ctx->allocated_size = sb.st_size;
  return 0;
}

static void _free_mounted_db(DB * db)
{
  if (_release_mounted(db) == 0)
  {
    munmap(db->mmap_ctx.addr, db->mmap_ctx.reserved_size);
    fclose(db->mmap_ctx.file);
    free(db);
  }
}

static int add_segment(DB * db)
{
  int grow = 1;
  node * seg;
  size_t _allocated_size;
  uint16_t cur_seg_nb;
  db_header * header = db->header;

  /* freelist exists ? */
  if (header->free_node != 0)
    return 0;

  /* can extend again ? */
  cur_seg_nb = header->seg_nb;
  if ((ADDR - grow) < cur_seg_nb)
    return -(ERANGE);

  /* now resize the database as needed */
  _allocated_size = sizeof(db_header) +
          (cur_seg_nb + grow) * db->cache.seg_sz * sizeof(node);
  if (ftruncate(fileno(db->mmap_ctx.file), _allocated_size) != 0)
    return -(EIO);

  /* map over and update the cache */
  if (_mmap_database(&(db->mmap_ctx)) < 0)
    return -(ENOMEM);
  db->cache.seg_nb += grow;

  /* new allocated space start at end */
  seg = db->data + (cur_seg_nb * db->cache.seg_sz);
  /* initialize free space */
  while (0 < grow--)
  {
    /* node id start from 1 */
    uint32_t newid = (cur_seg_nb << 16) + 1;
    node * _node = seg;
    int n;
    /* chain all members on front of the freelist */
    for (n = 1; n < db->cache.seg_sz; ++n)
    {
      _node->raw0 = newid + n;
      ++_node;
    }
    /* attach the segment and update freelist front */
    _node->raw0 = header->free_node;
    header->free_node = newid;
    header->seg_nb = ++cur_seg_nb;
    /* move to next segment */
    seg += db->cache.seg_sz;
  }
  return 1;
}

static node * get_node(DB * db, uint32_t node_id)
{
  if (node_id != 0)
  {
    uint16_t seg_no = (node_id >> 16) & 0x7fff;
    uint16_t pos_no = node_id & 0xffff;
    if (seg_no >= db->cache.seg_nb)
    {
      /* it is a corruption else the database has been extended */
      if (seg_no >= db->header->seg_nb ||
              _mmap_database(&(db->mmap_ctx)) < 0)
        return NULL;
      /* refresh cache */
      db->cache.seg_nb = db->header->seg_nb;
    }
    return &(db->data[seg_no * db->cache.seg_sz + pos_no - 1]); /* ids start from 1 */
  }
  /* return the root node */
  return get_node(db, db->header->root_node);
}

static node * new_node(DB * db, uint32_t * node_id)
{
  db_header * header = db->header;

  /* get node from freelist */
  if (header->free_node)
  {
    *node_id = header->free_node;
    node * freenode = get_node(db, *node_id);
    header->free_node = freenode->raw0 & ADDR;
    freenode->raw0 = 0;
    return freenode;
  }
  if (add_segment(db) > 0)
    return new_node(db, node_id);
  return NULL;
}

const char * db_format()
{
  return g_dbtag;
}

const char * db_name(DB *db)
{
  return db->header->db_name;
}

void rename_db(DB *db, const char * name)
{
  strncpy(db->header->db_name, name, 30);
}

static size_t _max_db_file_size(uint16_t seg_size)
{
  return ((ADDR >> 16) * seg_size * sizeof(node)) + sizeof (db_header);
}

DB * create_db(const char * filepath, const char * db_name, unsigned seg_size)
{
  struct stat filestat;
  db_header * tmp;
  DB * db;
  uint16_t ss;
  FILE * file;

  /* check file exists */
  if (stat(filepath, &filestat) == 0)
  {
    printf("ERROR: The file '%s' already exists\n", filepath);
    return NULL;
  }

  /* setup the segment size
   * max is fixed to 32768 nodes per segment */
  if ((ss = ((seg_size & 0xffff) / SEGS) * SEGS) < SEGS)
    ss = SEGS;
  else if (ss > 0x8000)
    ss = 0x8000;

  /* initialize the header */
  tmp = (db_header*) malloc(sizeof (db_header));
  if (!tmp)
    return NULL;
  memset(tmp, '\0', sizeof(db_header));
  memcpy(tmp->tag, g_dbtag, DBTAG_LEN);
  tmp->indianness = g_indianness;
  tmp->max_file_size = _max_db_file_size(ss);
  strncpy(tmp->db_name, db_name, 30);
  tmp->created = time(NULL);
  tmp->updated = tmp->created;
  tmp->seg_nb = 0;
  tmp->seg_sz = ss;
  tmp->free_node = 0;

  file = fopen(filepath, "wb");
  if (!file)
    goto fail0;
  if (fwrite(tmp, sizeof(db_header), 1, file) != 1)
    goto fail1;

  fclose(file);
  free(tmp);

  db = mount_db(filepath, 1);
  if (!db)
    return NULL;

  if (add_segment(db) != 1)
  {
    close_db(&db);
    return NULL;
  }
  new_node(db, &(db->header->root_node));
  return db;
fail1:
  fclose(file);
fail0:
  free(tmp);
  return NULL;
}

void stat_db(DB * db)
{
  db_header * header = db->header;
  printf("db_name     : %s\n", header->db_name);
  printf("created on  : %ld\n", header->created);
  printf("updated on  : %ld\n", header->updated);
  printf("db_cur_size : %u\n", (unsigned) db->mmap_ctx.allocated_size);
  printf("db_max_size : %u\n", (unsigned) db->mmap_ctx.reserved_size);
  printf("seg_size    : %u\n", (unsigned) header->seg_sz);
  printf("seg_count   : %u\n", (unsigned) header->seg_nb);
  printf("freelist    : %08x\n", header->free_node);
  printf("rootnode    : %08x\n", header->root_node);
}

void close_db(DB ** db)
{
  (*db)->destructor(*db);
  *db = NULL;
}

static int _create_record(DB * db, cidr_address * adr)
{
  node * n = get_node(db, 0);
  int b, v = 0, ln = adr->prefix - 1;

  for (b = 0; b < adr->prefix; ++b)
  {
    int c = b >> 3;
    int d = 7 - b + (c << 3);
    v = (adr->addr[c] >> d) & 0x1;
    //printf("%d ", v);

    /* corruption or failure */
    if (!n)
      return (-1);

    if (v == 0)
    {
      /* left branch */
      if ((n->raw0 & LEAF))
        return 0;
      if (b == ln)
        break;
      if (!(n->raw0 & ADDR))
        n = new_node(db, &(n->raw0));
      else
        n = get_node(db, n->raw0);
    }
    else
    {
      /* right branch */
      if ((n->raw1 & LEAF))
        return 0;
      if (b == ln)
        break;
      if (!(n->raw1 & ADDR))
        n = new_node(db, &(n->raw1));
      else
        n = get_node(db, n->raw1);
    }
  }

  /* corruption or failure */
  if (!n)
    return (-1);

  /* flag last node */
  if (v == 0)
    n->raw0 |= LEAF;
  else
    n->raw1 |= LEAF;
  //printf("n %p = %d , %d\n", n, (n->raw0 & LEAF) >> 31, (n->raw1 & LEAF) >> 31);
  return 1;
}

int create_record(DB * db, cidr_address * adr)
{
  int r = _create_record(db, adr);
  if (r > 0)
    db->header->updated = time(NULL);
  return r;
}

int find_record(DB * db, cidr_address * adr)
{
  node * n = get_node(db, 0);
  int b, v = 0;

  for (b = 0; b < adr->prefix; ++b)
  {
    int c = b >> 3;
    int p = 7 - b + (c << 3);

    /* corruption or failure */
    if (!n)
      return (-1);

    v = (adr->addr[c] >> p) & 0x1;
    if (v == 0)
    {
      /* left branch */
      if ((n->raw0 & LEAF))
        return 1;
      if (!(n->raw0 & ADDR))
        return 0;
      n = get_node(db, n->raw0);
    }
    else
    {
      /* right branch */
      if ((n->raw1 & LEAF))
        return 1;
      if (!(n->raw1 & ADDR))
        return 0;
      n = get_node(db, n->raw1);
    }
  }
  return 0;
}

static int _read_db_header(db_header * header, FILE * file)
{
  char * addr;
  rewind(file);
  if (fread(header, sizeof(db_header), 1, file) != 1)
    return -(EIO);
  addr = (char*) header;
  /* check tag */
  if (memcmp(addr, g_dbtag, DBTAG_LEN) != 0)
    return -(EINVAL);
  addr += DBTAG_LEN;
  /* check endianness */
  if (memcmp(addr, &g_indianness, sizeof (uint32_t)) != 0)
    return -(EINVAL);
  return 0;
}

DB * mount_db(const char * filepath, int rw)
{
  mmap_ctx mmap_ctx;
  char * addr;
  DB * db;
  db_header * file_header;
  FILE * file;

  /* return the already mounted db */
  if ((db = _hold_mounted(filepath)))
    return db;

  /* mount the db */
  if (rw)
    file = fopen(filepath, "rb+");
  else
    file = fopen(filepath, "rb");
  if (!file)
    return NULL;

  file_header = (db_header*) malloc(sizeof(db_header));
  if (!file_header)
    goto fail0;
  if (_read_db_header(file_header, file) < 0)
    goto fail1;

  /* reserve the whole size */
  mmap_ctx.reserved_size = file_header->max_file_size;
  mmap_ctx.addr = _mmap_reserve(mmap_ctx.reserved_size);
  if (!mmap_ctx.addr)
    goto fail1;

  /* load the database */
  mmap_ctx.flag_rw = rw;
  mmap_ctx.file = file;
  if (_mmap_database(&mmap_ctx) < 0)
    goto fail2;

  /* allocated size cannot be less than stated from file header */
  if (mmap_ctx.allocated_size < sizeof(db_header) +
          (file_header->seg_nb * file_header->seg_sz * sizeof (node)))
    goto fail3;

  addr = (char*) mmap_ctx.addr;

  db = (DB*) malloc(sizeof (DB));
  if (!db)
    goto fail2;
  /* keep in cache the older known state, therefore from file header */
  db->cache.seg_nb = file_header->seg_nb;
  db->cache.seg_sz = file_header->seg_sz;
  free(file_header);

  /* init the database */
  db->header = (db_header*) addr;
  db->destructor = _free_mounted_db;
  db->mmap_ctx = mmap_ctx;
  db->data = (node *) (addr + sizeof (db_header));

  /* register the mounted db */
  _register_mounted(filepath, db);
  return db;
fail3:
  free(db);
fail2:
  munmap(mmap_ctx.addr, mmap_ctx.reserved_size);
fail1:
  free(file_header);
fail0:
  fclose(file);
  return NULL;
}

int create_cidr_address(cidr_address * cidr, const char * cidr_str)
{
  if (sscanf(cidr_str, "%hhd.%hhd.%hhd.%hhd/%d",
             &(cidr->addr[0]), &(cidr->addr[1]), &(cidr->addr[2]),
             &(cidr->addr[3]), &(cidr->prefix)) != 5)
    return -(EINVAL);
  if (cidr->prefix < 0 || cidr->prefix > (8 * ADDR_SZ))
    return -(EINVAL);
  return 0;
}

int create_cidr_address_2(cidr_address * cidr, const char * addr_str, int prefix)
{
  if (sscanf(addr_str, "%hhd.%hhd.%hhd.%hhd",
             &(cidr->addr[0]), &(cidr->addr[1]), &(cidr->addr[2]),
             &(cidr->addr[3])) != 4)
    return -(EINVAL);
  if (prefix < 0 || prefix > (8 * ADDR_SZ))
    return -(EINVAL);
  cidr->prefix = prefix;
  return 0;
}

static unsigned _readln(char * buf, unsigned n, FILE * file)
{
  unsigned r = 0;
  int c;
  while (r < n)
  {
    if ((c = fgetc(file)) <= 0)
      break;
    /* bypass CTRL+R */
    if (c == '\r')
      continue;
    ++r;
    *buf = (char) c;
    if (c == '\n')
      break;
    ++buf;
  }
  return r;
}

int fill_database_from_text(DB * db, const char * filepath)
{
  FILE* file = fopen(filepath, "r");
  char buf[256];
  unsigned r = 0, l = 0, c = 0;
  if (!file)
    return -(ENOENT);
  while ((r = _readln(buf, sizeof (buf) - 1, file)))
  {
    ++l; /* for debug */
    /* read line must be terminated by CTRL+N */
    if (buf[r - 1] != '\n')
      break;
    /* convert to string ending with zero */
    buf[r - 1] = '\0';
    /* trim spaces */
    char * p = buf;
    while (*p == ' ')
    {
      ++p;
    }
    /* discard comment or empty line */
    if (*p == '#' || (p - buf + 1) == r)
      continue;
    //printf("parse address %s\n", buf);
    cidr_address adr;
    if (create_cidr_address(&adr, buf) < 0)
      break;
    if (_create_record(db, &adr) < 0)
      break;
    ++c;
  }
  fclose(file);
  if (c > 0)
    db->header->updated = time(NULL);
  if (r == 0)
    return 0;
  buf[r] = '\0';
  printf("ERROR: Insertion failed on '%s' at line %d.\n", buf, l);
  return -(EINVAL);
}
