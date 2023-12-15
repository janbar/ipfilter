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

/**
 * DATABASE CONCEPT
 *   The database store 2 types of chained structure: the data tree and
 *   the free list. Those structures are similar, meaning a sub-tree of data
 *   can be linked in the free list.
 *   This allows for quick updating and deleting. Insertion is just as fast,
 *   because here we consume at the root of the free list to grow a branch of
 *   data. The free list is auto balanced.
 *
 * TREE STRUCTURE
 *
 * BIT                             0              1
 *                         +--------------+--------------+
 *  N                      | 00 0x05F004E | 00 0x05F0058 |
 *                         +-------+------+-------+------+
 *                                 |  NODE        |  NODE
 *                                 V              V
 *       +--------------+--------------+      +--------------+--------------+
 * N+1   | [10] 0x00000 | 00 0x05F00A2 |      | [01] 0x00000 | [00] 0x00000 |
 *       +--------------+-------+------+      +--------------+--------------+
 *         LEAF 2=DENY          |  NODE         LEAF 1=ALLOW       EMPTY
 *                              V
 *                         +--------------+--------------+
 * N+2                     | [01] 0x00000 | [10] 0x00000 |
 *                         +--------------+--------------+
 *                           LEAF 1=ALLOW   LEAF 2=DENY
 *
 * 0.. = undefined
 * 00. = deny
 * 01. = undefined
 * 010 = allow
 * 011 = deny
 * 1.. = undefined
 * 10. = allow
 * 11. = undefined
 */

#include "db.h"

#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <inttypes.h>

#define DBTAG_LEN 4
static const char * g_dbtag = "IPF4";
static const int g_indianness = 0xFF000000;

#define SEGS        0x100      /* base of segment size */
#define ADDR        0x3FFFFFFF /* 30 bits size */
#define SEG_RANGE   0x3FFF
#define NOD_RANGE   0xFFFF

#define SEGMENT_SIZE(m) ((unsigned)(m) + 1)

#define LEAF        0xC0000000
#define LEAF_ALLOW  0x40000000
#define LEAF_DENY   0x80000000

#define LEAF_VALUE(u)   ((db_response)(((u) >> 30) & 0x3))

typedef struct
{
  char      tag[4];
  uint32_t  indianness;
  uint64_t  max_file_size;
  char      db_name[32];
  int64_t   created;
  int64_t   updated;

  uint16_t  seg_nb;         /* nb extents */
  uint16_t  seg_mask;       /* id range mask */
  uint32_t  free_addr;      /* front of freelist (node addr) */
  uint32_t  root_addr;      /* addr of the root node */
  char      _padding[4];    /* reserved */
} db_header;

typedef struct
{
  uint32_t  raw0;           /* 2 bits leaf, 30 bit addr */
  uint32_t  raw1;           /* 2 bits leaf, 30 bit addr */
} node;

typedef struct
{
  void *    addr;
  size_t    reserved_bytes;   /* rounded up _SC_PAGESIZE */
  size_t    allocated_bytes;  /* rounded up _SC_PAGESIZE */
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
    unsigned seg_sz;
  } cache;
};

typedef struct mounted mounted;

struct mounted
{
  DB *       db;
  uint32_t   hash;
  volatile uint32_t refcount;
  mounted *  _prev;
  mounted *  _next;
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

static size_t _mmap_roundup_size(size_t size)
{
  size_t _size;
  size_t page_size = (size_t) sysconf(_SC_PAGESIZE);
  _size = (size / page_size) * page_size;
  if (_size < size)
    _size += page_size;
  return _size;
}

static void * _mmap_reserve(size_t * size)
{
  void * addr;
  size_t _size = _mmap_roundup_size(*size);

  addr = mmap(NULL, _size, PROT_NONE, MAP_ANON|MAP_PRIVATE, -1, 0);
  if (addr == MAP_FAILED)
    return NULL;
  *size = _size;
  return addr;
}

static int _mmap_database(mmap_ctx * ctx)
{
  void * addr;
  struct stat sb;
  size_t size;
  int prot, fd;

  /* check context */
  if (!ctx->file || !ctx->addr)
    return -(EINVAL);
  /* stat for size to allocate */
  fd = fileno(ctx->file);
  if (fstat(fd, &sb) == -1)
    return -(EIO);
  /* check reserved address space */
  if (sb.st_size > (off_t) ctx->reserved_bytes)
    return -(ERANGE);

  size = _mmap_roundup_size((size_t) sb.st_size);
  prot = PROT_READ;
  if (ctx->flag_rw)
    prot |= PROT_WRITE;

  addr = mmap(ctx->addr, size, prot, MAP_FIXED|MAP_SHARED, fd, 0);
  if (addr == MAP_FAILED)
    return -(ENOMEM);
  /* mmap succeeded */
  ctx->allocated_bytes = size;
  return 0;
}

static void _free_mounted_db(DB * db)
{
  if (_release_mounted(db) == 0)
  {
    /* free allocated space */
    munmap(db->mmap_ctx.addr, db->mmap_ctx.allocated_bytes);
    /* free the rest of reserved space */
    if (db->mmap_ctx.reserved_bytes > db->mmap_ctx.allocated_bytes)
    {
      void * addr = (char*)(db->mmap_ctx.addr) + db->mmap_ctx.allocated_bytes;
      munmap(addr, db->mmap_ctx.reserved_bytes - db->mmap_ctx.allocated_bytes);
    }
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
  if (header->free_addr != 0)
    return 0;

  /* can extend again ? */
  cur_seg_nb = header->seg_nb;
  if ((ADDR - (grow << 16)) < (cur_seg_nb << 16))
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
    /* seg no start from 1 */
    uint32_t addr = ((cur_seg_nb + 1) << 16);
    node * _node = seg;
    unsigned n;
    /* chain all members on front of the freelist */
    for (n = 1; n < db->cache.seg_sz; ++n)
    {
      _node->raw0 = addr + n;
      _node->raw1 = 0;
      ++_node;
    }
    /* attach the segment and update freelist front */
    _node->raw0 = header->free_addr;
    _node->raw1 = 0;
    header->free_addr = addr;
    header->seg_nb = ++cur_seg_nb;
    /* move to next segment */
    seg += db->cache.seg_sz;
  }
  return 1;
}

/**
 * Returns a pointer to node
 * WARNING: no check of the vector address is done, therefore the given value
 * must be checked before calling this: i.e (node_id & ADDR) != 0.
 * Calling for 0 will return the root node.
 */
static node * get_node(DB * db, uint32_t node_id)
{
  if (node_id != 0)
  {
    uint16_t seg_no = (node_id >> 16) & SEG_RANGE;
    uint16_t pos_no = node_id & NOD_RANGE;
    if (seg_no > db->cache.seg_nb)
    {
      /* it is a corruption else the database has been extended */
      if (seg_no > db->header->seg_nb ||
              _mmap_database(&(db->mmap_ctx)) < 0)
        return NULL;
      /* refresh cache */
      db->cache.seg_nb = db->header->seg_nb;
    }
    /* seg no start from 1 */
    return &(db->data[(seg_no - 1) * db->cache.seg_sz + pos_no]);
  }
  /* return the root node */
  return get_node(db, db->header->root_addr);
}

static node * new_node(DB * db, uint32_t * node_id)
{
  db_header * header = db->header;

  /* get node from freelist */
  if (header->free_addr)
  {
    /* chain the new node (ADDR) */
    *node_id = header->free_addr;
    node * freenode = get_node(db, *node_id);

    if (freenode->raw0 & ADDR)
    {
      header->free_addr = freenode->raw0 & ADDR;

      /* move the right branch to next end at right
       * by doing that, the cost is the lowest */
      if ((freenode->raw1 & ADDR))
      {
        node * _node = get_node(db, freenode->raw0);
        while (_node && (_node->raw1 & ADDR))
          _node = get_node(db, _node->raw1);
        if (!_node)
          return NULL; /* corruption */
        _node->raw1 = freenode->raw1;
      }
    }
    else
    {
      /* here reorg is not necessary */
      header->free_addr = freenode->raw1 & ADDR;
    }

    /* clear the new node before returning */
    freenode->raw0 = 0;
    freenode->raw1 = 0;
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

const char * db_name(DB * db)
{
  return db->header->db_name;
}

void rename_db(DB *db, const char * name)
{
  strncpy(db->header->db_name, name, 30);
}

static size_t _max_db_file_size(uint16_t seg_mask)
{
  return ((ADDR >> 16) * SEGMENT_SIZE(seg_mask) * sizeof(node)) + sizeof (db_header);
}

DB * create_db(const char * filepath, const char * db_name, unsigned seg_size)
{
  struct stat filestat;
  db_header * tmp;
  DB * db;
  uint16_t seg_mask;
  FILE * file;

  /* check file exists */
  if (stat(filepath, &filestat) == 0)
  {
    printf("ERROR: The file '%s' already exists\n", filepath);
    return NULL;
  }

  /* define the segment size (id range) */
  {
    unsigned sz = SEGS;
    while (seg_size > sz) sz = sz << 1;
    seg_mask = (sz - 1) & NOD_RANGE;
  }

  /* initialize the header */
  tmp = (db_header*) malloc(sizeof (db_header));
  if (!tmp)
    return NULL;
  memset(tmp, '\0', sizeof(db_header));
  memcpy(tmp->tag, g_dbtag, DBTAG_LEN);
  tmp->indianness = g_indianness;
  tmp->max_file_size = _max_db_file_size(seg_mask);
  strncpy(tmp->db_name, db_name, 30);
  tmp->created = time(NULL);
  tmp->updated = tmp->created;
  tmp->seg_nb = 0;
  tmp->seg_mask = seg_mask;
  tmp->free_addr = 0;
  tmp->root_addr = ADDR; /* invalidate the db until creation is complete */

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
  /* set the root node */
  new_node(db, &(db->header->root_addr));
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
  printf("db_name    : %s\n", header->db_name);
  printf("created    : %" PRId64 "\n", (int64_t)header->created);
  printf("updated    : %" PRId64 "\n", (int64_t)header->updated);
  printf("db_cur_size: %" PRIu64 "\n", (uint64_t)db->mmap_ctx.allocated_bytes);
  printf("db_max_size: %" PRIu64 "\n", (uint64_t)db->mmap_ctx.reserved_bytes);
  printf("seg_size   : %u\n", SEGMENT_SIZE(header->seg_mask));
  printf("seg_count  : %u\n", (unsigned)header->seg_nb);
  printf("freelist   : %08x\n", header->free_addr);
  printf("rootnode   : %08x\n", header->root_addr);
}

void close_db(DB ** db)
{
  (*db)->destructor(*db);
  *db = NULL;
}

static int _give_back_tree(DB * db, uint32_t node_id)
{
  if ((node_id & ADDR))
  {
    node * _node = get_node(db, node_id);
    /* go to leaf */
    while (_node && (_node->raw0 & ADDR))
      _node = get_node(db, _node->raw0);
    if (!_node)
      return (-1); /* corruption */
    _node->raw0 = db->header->free_addr;
    db->header->free_addr = (node_id & ADDR);
  }
  return 0;
}

static db_response _create_record(DB * db, cidr_address * cidr, uint32_t leaf_mask)
{
  node * n = get_node(db, 0);
  int b, v = 0, ln = cidr->prefix - 1;
  uint32_t inherit = 0;

  for (b = 0; b < cidr->prefix; ++b)
  {
    int c = b >> 3;
    int d = 7 - b + (c << 3);
    v = (cidr->addr[c] >> d) & 0x1;
    //printf("%d ", v);

    /* corruption or failure */
    if (!n)
      return db_error;

    /* left branch */
    if (v == 0)
    {
      if (b == ln)
        break; /* make the leaf here */
      /* next node */
      if ((n->raw0 & ADDR))
        n = get_node(db, n->raw0);
      else if ((n->raw0 & leaf_mask))
        return LEAF_VALUE(leaf_mask); /* already exists */
      else
      {
        /* start a new branch ? */
        if (!inherit)
          inherit = n->raw0 & LEAF;
        /* make node */
        n = new_node(db, &(n->raw0));
        if (!n)
          return db_error;
        /* make new leaf inherit */
        n->raw0 = inherit;
        n->raw1 = inherit;
      }
    }
    /* right branch */
    else
    {
      if (b == ln)
        break; /* make the leaf here */
      /* next node */
      if ((n->raw1 & ADDR))
        n = get_node(db, n->raw1);
      else if ((n->raw1 & leaf_mask))
        return LEAF_VALUE(leaf_mask); /* already exists */
      else
      {
        /* start a new branch ? */
        if (!inherit)
          inherit = n->raw1 & LEAF;
        /* make node */
        n = new_node(db, &(n->raw1));
        if (!n)
          return db_error;
        /* make new leaf inherit */
        n->raw0 = inherit;
        n->raw1 = inherit;
      }
    }
  }

  /* corruption or failure */
  if (!n)
    return db_error;

  /* make the leaf */
  if (ln < 0)
  {
    if (_give_back_tree(db, n->raw0) < 0 || _give_back_tree(db, n->raw1) < 0)
      return db_error;
    n->raw0 = leaf_mask;
    n->raw1 = leaf_mask;
  }
  else if (v == 0)
  {
    if (_give_back_tree(db, n->raw0) < 0)
      return db_error;
    if ((n->raw0 & leaf_mask))
      return LEAF_VALUE(leaf_mask); /* already exists */
    n->raw0 = leaf_mask;
  }
  else
  {
    if (_give_back_tree(db, n->raw1) < 0)
      return db_error;
    if ((n->raw1 & leaf_mask))
      return LEAF_VALUE(leaf_mask); /* already exists */
    n->raw1 = leaf_mask;
  }
  //printf("n %p = %d , %d\n", n, LEAF_VALUE(n->raw0), LEAF_VALUE(n->raw1));
  return db_not_found;
}

db_response insert_cidr(DB * db, cidr_address * cidr, db_rule rule)
{
  switch (rule)
  {
  case rule_allow:
    return _create_record(db, cidr, LEAF_ALLOW);
  case rule_deny:
    return _create_record(db, cidr, LEAF_DENY);
  }
  return db_error;
}

void db_updated(DB * db)
{
  db->header->updated = time(NULL);
}

db_response find_record(DB * db, cidr_address * cidr)
{
  node * n = get_node(db, 0);
  int b, v = 0;

  for (b = 0; b < cidr->prefix; ++b)
  {
    int c = b >> 3;
    int p = 7 - b + (c << 3);

    /* corruption or failure */
    if (!n)
      return db_error;

    v = (cidr->addr[c] >> p) & 0x1;
    if (v == 0)
    {
      /* left branch */
      if (!(n->raw0 & ADDR))
        return LEAF_VALUE(n->raw0 & LEAF);
      n = get_node(db, n->raw0);
    }
    else
    {
      /* right branch */
      if (!(n->raw1 & ADDR))
        return LEAF_VALUE(n->raw1 & LEAF);
      n = get_node(db, n->raw1);
    }
  }
  return db_not_found;
}

void purge_db(DB * db)
{
  unsigned s;
  node * seg = db->data;
  db_header * header = db->header;

  db->data->raw0 = 0;
  db->data->raw1 = 0;
  header->free_addr = 0;

  for (s = 0; s < db->cache.seg_nb; ++s)
  {
    /* seg no start from 1 */
    uint32_t addr = ((s + 1) << 16);
    node * _node = seg;
    unsigned n;
    /* chain all members on front of the freelist */
    for (n = 1; n < db->cache.seg_sz; ++n)
    {
      _node->raw0 = addr + n;
      _node->raw1 = 0;
      ++_node;
    }
    /* attach the segment and update freelist front */
    _node->raw0 = header->free_addr;
    _node->raw1 = 0;
    header->free_addr = addr;
    /* move to next segment */
    seg += db->cache.seg_sz;
  }
  new_node(db, &(header->root_addr));
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
  mmap_ctx.reserved_bytes = file_header->max_file_size;
  mmap_ctx.addr = _mmap_reserve(&mmap_ctx.reserved_bytes);
  if (!mmap_ctx.addr)
    goto fail1;

  /* load the database */
  mmap_ctx.flag_rw = rw;
  mmap_ctx.file = file;
  if (_mmap_database(&mmap_ctx) < 0)
    goto fail2;

  /* allocated size cannot be less than stated from file header */
  if (mmap_ctx.allocated_bytes < sizeof(db_header) +
          (file_header->seg_nb * SEGMENT_SIZE(file_header->seg_mask) * sizeof (node)))
    goto fail3;

  addr = (char*) mmap_ctx.addr;

  db = (DB*) malloc(sizeof (DB));
  if (!db)
    goto fail2;
  /* keep in cache the older known state, therefore from file header */
  db->cache.seg_nb = file_header->seg_nb;
  db->cache.seg_sz = SEGMENT_SIZE(file_header->seg_mask);
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
  munmap(mmap_ctx.addr, mmap_ctx.reserved_bytes);
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

int create_cidr_address_2(cidr_address * cidr,
                          const char * addr_str, int prefix)
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
