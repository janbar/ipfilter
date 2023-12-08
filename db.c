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
#include <sys/mman.h>
#include <sys/stat.h>

#define DBTAG_LEN 4
static const char * g_dbtag = "IPF2";
static const int g_indianness = 0xff000000;

#define SEGS 0x200      /* base of segment size */
#define LEAF 0x80000000 /* bit 31 */
#define ADDR 0x7fffffff /* bit 30-0 */

typedef struct
{
  uint16_t  segment_count;  /* nb extents */
  uint16_t  segment_size;   /* segment size */
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
  size_t    bytes;
} mmap_ctx;

struct DB
{
  db_header * header;
  node **   data;
  void (*destructor)(DB*);
  mmap_ctx mmap_ctx;
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

static int add_segment(DB * db)
{
  int grow = 1;
  uint16_t osz;
  node ** new;
  db_header * header = db->header;

  /* freelist exists ? */
  if (header->free_node != 0)
    return 0;
  /* grow the segment array */
  osz = header->segment_count;
  if ((ADDR - grow) < osz)
    return -(ERANGE);
  if (osz == 0)
    new = (node**) calloc(grow, sizeof (node*));
  else
    new = (node**) realloc(db->data, sizeof (node*) * (osz + grow));
  if (!new)
    return -(ENOMEM);
  db->data = new;
  /* initialize new segment(s) */
  while (0 < grow--)
  {
    int n;
    node * _node;
    node * seg = (node*) calloc(header->segment_size, sizeof (node));

    if (!seg)
      return -(ENOMEM);
    /* chain all members on front of the freelist */
    _node = seg;
    for (n = 1; n < header->segment_size; ++n)
    {
      _node->raw0 = (osz << 16) + n + 1; /* ids start from 1 */
      _node++;
    }
    /* attach the segment and update freelist front */
    db->data[osz] = seg;
    _node->raw0 = header->free_node;
    header->free_node = (osz << 16) + 1; /* ids start from 1 */
    header->segment_count = ++osz;
  }
  return 1;
}

static node * get_node(DB * db, uint32_t node_id)
{
  if (node_id != 0)
  {
    uint32_t segment = (node_id >> 16) & 0x7fff;
    uint32_t nodenum = (node_id & 0xffff);
    return &(db->data[segment][nodenum - 1]); /* ids start from 1 */
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

static void _free_db(DB * db)
{
  /* free data */
  if (db->data)
  {
    int s;
    for (s = 0; s < db->header->segment_count; ++s)
    {
      free(db->data[s]);
    }
    free(db->data);
  }
  /* free header */
  if (db->header)
    free(db->header);
  /* free db skeleton */
  free(db);
}

const char * db_format()
{
  return g_dbtag;
}

DB * create_db(unsigned seg_size)
{
  db_header * header;
  uint16_t n = (seg_size & 0xffff) / SEGS;
  DB * db = (DB*) malloc(sizeof (DB));
  if (!db)
    return NULL;
  memset(db, '\0', sizeof (DB));
  header = (db_header*) malloc(sizeof (db_header));
  if (!header)
  {
    _free_db(db);
    return NULL;
  }
  header->segment_count = 0;
  header->segment_size = (n == 0 ? SEGS : n * SEGS);
  header->free_node = 0;
  db->header = header;
  db->destructor = _free_db;
  if (add_segment(db) != 1)
  {
    _free_db(db);
    return NULL;
  }
  new_node(db, &(db->header->root_node));
  return db;
}

void stat_db(DB * db)
{
  db_header * header = db->header;
  printf("%s: segcnt=%u segsz=%u freelist=%08x rootnode=%08x totsz=%lu\n",
         __FUNCTION__,
         (unsigned) header->segment_count,
         (unsigned) header->segment_size,
         header->free_node,
         header->root_node,
         header->segment_count * header->segment_size * sizeof (node));
}

void close_db(DB ** db)
{
  (*db)->destructor(*db);
  *db = NULL;
}

int create_record(DB * db, cidr_address * adr)
{
  node * n = get_node(db, 0);
  int b, v = 0, ln = adr->prefix - 1;

  for (b = 0; b < adr->prefix; ++b)
  {
    int c = b >> 3;
    int d = 7 - b + (c << 3);
    v = (adr->addr[c] >> d) & 0x1;
    //printf("%d ", v);
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
  // flag last node
  if (v == 0)
    n->raw0 |= LEAF;
  else
    n->raw1 |= LEAF;
  //printf("n %p = %d , %d\n", n, (n->raw0 & LEAF) >> 31, (n->raw1 & LEAF) >> 31);
  return 1;
}

int find_record(DB * db, cidr_address * adr)
{
  node * n = get_node(db, 0);
  int b, v = 0;

  for (b = 0; b < adr->prefix; ++b)
  {
    int c = b >> 3;
    int p = 7 - b + (c << 3);
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

int write_db_file(DB * db, const char * filepath)
{
  int i;
  db_header * header = db->header;
  FILE * file = fopen(filepath, "wb+");

  if (!file)
    return -(ENOENT);
  /* write tag */
  if (fwrite(g_dbtag, DBTAG_LEN, 1, file) != 1)
    goto fail;
  /* write indianess check */
  if (fwrite(&g_indianness, sizeof (int), 1, file) != 1)
    goto fail;
  /* write header */
  if (fwrite(header, sizeof (db_header), 1, file) != 1)
    goto fail;
  /* write data */
  for (i = 0; i < header->segment_count; ++i)
  {
    if (fwrite(db->data[i], sizeof (node), header->segment_size, file)
            != header->segment_size)
      goto fail;
  }
  fclose(file);
  return 0;
fail:
  fclose(file);
  return -(EIO);
}

static void * mmap_database(int fd, size_t * bytes)
{
  void * addr;
  struct stat sb;
  /* file size */
  if (fstat(fd, &sb) == -1)
    return NULL;
  addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (addr == MAP_FAILED)
    return NULL;
  /* mmap succeeded */
  *bytes = sb.st_size;
  return addr;
}

static void _free_mounted_db(DB * db)
{
  if (_release_mounted(db) == 0)
  {
    munmap(db->mmap_ctx.addr, db->mmap_ctx.bytes);
    if (db->data)
      free(db->data);
    free(db);
  }
}

#define DBFILE_HEADER_SZ (DBTAG_LEN + sizeof(int) + sizeof(db_header))

DB * mount_db(const char * filepath)
{
  int i;
  mmap_ctx mmap_ctx;
  char * addr;
  DB * db;
  db_header * header;
  FILE * file;

  /* return the already mounted db */
  if ((db = _hold_mounted(filepath)))
    return db;

  /* mount the db */
  if (!(file = fopen(filepath, "rb")))
    return NULL;
  mmap_ctx.addr = mmap_database(fileno(file), &mmap_ctx.bytes);
  if (!mmap_ctx.addr)
    goto fail0;
  /* check mmap size for the header */
  if (mmap_ctx.bytes < DBFILE_HEADER_SZ)
    goto fail1;
  /* check tag */
  addr = (char*) mmap_ctx.addr;
  if (memcmp(addr, g_dbtag, DBTAG_LEN) != 0)
    goto fail1;
  addr += DBTAG_LEN;
  /* check endianness */
  if (memcmp(addr, &g_indianness, sizeof (int)) != 0)
    goto fail1;
  addr += sizeof (int);
  /* initialize database */
  db = (DB*) malloc(sizeof (DB));
  if (!db)
    goto fail1;
  header = (db_header*) addr;
  addr += sizeof (db_header);
  /* check mmap size for the rest */
  if (mmap_ctx.bytes < DBFILE_HEADER_SZ +
          (header->segment_count * header->segment_size * sizeof (node)))
    goto fail2;
  /* init the database */
  db->destructor = _free_mounted_db;
  db->mmap_ctx = mmap_ctx;
  db->header = header;
  /* initialize data array */
  db->data = (node**) calloc(header->segment_count, sizeof (node*));
  if (!db->data)
    goto fail2;
  /* link data segments */
  for (i = 0; i < header->segment_count; ++i)
  {
    db->data[i] = (node*) addr;
    addr += header->segment_size * sizeof (node);
  }
  /* register the mounted db */
  _register_mounted(filepath, db);
  fclose(file);
  return db;
fail2:
  free(db);
fail1:
  munmap(mmap_ctx.addr, mmap_ctx.bytes);
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
  unsigned r = 0, l = 0;
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
    create_record(db, &adr);
  }
  fclose(file);
  if (r == 0)
    return 0;
  buf[r] = '\0';
  printf("ERROR: Invalid value '%s' at line %d.\n", buf, l);
  return -(EINVAL);
}
