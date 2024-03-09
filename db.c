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
 *   The database stores 2 types of chained structure: the data tree and
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
#include <arpa/inet.h>

#define DBTAG_LEN 4
static const char * ipf_dbtag = "IPF4";
static const int ipf_bom = 0xFF000000;

#define SEGS        0x100      /* base of segment size */
#define ADDR        0x3FFFFFFF /* 30 bits size */
#define SEG_RANGE   0x3FFF
#define NOD_RANGE   0xFFFF

#define SEGMENT_SIZE(m) ((unsigned)(m) + 1)

#define LEAF        0xC0000000
#define LEAF_ALLOW  0x40000000
#define LEAF_DENY   0x80000000

#define LEAF_VALUE(u)   ((ipf_response)(((u) >> 30) & 0x3))

#define V4MAPPED_1BIT   (8 * (IPF_ADDR_SZ - 4))

#define ADDR_IS_V4MAPPED(a) (\
  (*(const uint32_t *)(const void *)(&(a[0])) == 0) && \
  (*(const uint32_t *)(const void *)(&(a[4])) == 0) && \
  (*(const uint32_t *)(const void *)(&(a[8])) == ntohl(0x0000ffff)))

static const unsigned char ipf_addr4_init[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 };

static const unsigned char ipf_addr6_init[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

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
  uint32_t  root4_addr;     /* addr of the root node for ipv4 tree */
  uint32_t  root6_addr;     /* addr of the root node for ipv6 tree */
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

struct IPF_DB
{
  db_header * header;
  node *      data;
  void (*destructor)(IPF_DB*);
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
  IPF_DB *       db;
  uint32_t   hash;
  volatile uint32_t refcount;
  mounted *  _prev;
  mounted *  _next;
};

static mounted * ipf_mounted = NULL;

static uint32_t ipf_hash(uint32_t maxsize, const char * buf, unsigned len)
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

static IPF_DB * ipf_hold_mounted(const char * filepath)
{
  uint32_t h = ipf_hash(0xffffffff, filepath, strlen(filepath));
  mounted * m = ipf_mounted;
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

static void ipf_register_mounted(const char * filepath, IPF_DB * db)
{
  mounted * m = (mounted*) malloc(sizeof(mounted));
  m->db = db;
  m->hash = ipf_hash(0xffffffff, filepath, strlen(filepath));
  m->refcount = 1;
  m->_prev = NULL;
  m->_next = NULL;
  if (ipf_mounted)
  {
    m->_next = ipf_mounted;
    ipf_mounted->_prev = m;
  }
  ipf_mounted = m;
}

static int ipf_release_mounted(IPF_DB * db)
{
  mounted * m = ipf_mounted;
  while (m)
  {
    if (m->db == db)
    {
      if (m->refcount > 1)
        return --(m->refcount);
      /* free */
      if (!m->_prev && !m->_next)
        ipf_mounted = NULL;
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

static size_t ipf_mmap_roundup_size(size_t size)
{
  size_t _size;
  size_t page_size = (size_t) sysconf(_SC_PAGESIZE);
  _size = (size / page_size) * page_size;
  if (_size < size)
    _size += page_size;
  return _size;
}

static void * ipf_mmap_reserve(size_t * size)
{
  void * addr;
  size_t _size = ipf_mmap_roundup_size(*size);

  addr = mmap(NULL, _size, PROT_NONE, MAP_ANON|MAP_PRIVATE, -1, 0);
  if (addr == MAP_FAILED)
    return NULL;
  *size = _size;
  return addr;
}

static int ipf_mmap_database(mmap_ctx * ctx)
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

  size = ipf_mmap_roundup_size((size_t) sb.st_size);
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

static void ipf_free_mounted_db(IPF_DB * db)
{
  if (ipf_release_mounted(db) == 0)
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

static int ipf_add_segment(IPF_DB * db)
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
  if (ipf_mmap_database(&(db->mmap_ctx)) < 0)
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
 */
static node * ipf_get_node(IPF_DB * db, uint32_t node_id)
{
  uint16_t seg_no = (node_id >> 16) & SEG_RANGE;
  uint16_t pos_no = node_id & NOD_RANGE;
  if (seg_no == 0)
    return NULL;
  if (seg_no > db->cache.seg_nb)
  {
    /* it is a corruption else the database has been extended */
    if (seg_no > db->header->seg_nb ||
            ipf_mmap_database(&(db->mmap_ctx)) < 0)
      return NULL;
    /* refresh cache */
    db->cache.seg_nb = db->header->seg_nb;
  }
  /* seg no start from 1 */
  return &(db->data[(seg_no - 1) * db->cache.seg_sz + pos_no]);
}

static node * ipf_new_node(IPF_DB * db, uint32_t * node_id)
{
  db_header * header = db->header;

  /* get node from freelist */
  if (header->free_addr)
  {
    uint32_t freeaddr = header->free_addr;
    node * freenode = ipf_get_node(db, freeaddr);

    if (freenode->raw0 & ADDR)
    {
      header->free_addr = freenode->raw0 & ADDR;

      /* move the right branch to next end at right
       * by doing that, the cost is the lowest */
      if ((freenode->raw1 & ADDR))
      {
        node * _node = ipf_get_node(db, freenode->raw0);
        while (_node && (_node->raw1 & ADDR))
          _node = ipf_get_node(db, _node->raw1);
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

    /* clear the new node */
    freenode->raw0 = 0;
    freenode->raw1 = 0;
    /* chain the new node */
    *node_id = freeaddr;
    return freenode;
  }
  if (ipf_add_segment(db) > 0)
    return ipf_new_node(db, node_id);
  return NULL;
}

const char * ipf_db_format()
{
  return ipf_dbtag;
}

const char * ipf_db_name(IPF_DB * db)
{
  return db->header->db_name;
}

void ipf_rename_db(IPF_DB *db, const char * name)
{
  strncpy(db->header->db_name, name, 30);
}

static size_t ipf_max_db_file_size(uint16_t seg_mask)
{
  return ((ADDR >> 16) * SEGMENT_SIZE(seg_mask) * sizeof(node)) + sizeof (db_header);
}

IPF_DB * ipf_create_db(const char * filepath, const char * db_name, unsigned seg_size)
{
  struct stat filestat;
  db_header * tmp;
  IPF_DB * db;
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
  memcpy(tmp->tag, ipf_dbtag, DBTAG_LEN);
  tmp->indianness = ipf_bom;
  tmp->max_file_size = ipf_max_db_file_size(seg_mask);
  strncpy(tmp->db_name, db_name, 30);
  tmp->created = time(NULL);
  tmp->updated = tmp->created;
  tmp->seg_nb = 0;
  tmp->seg_mask = seg_mask;
  tmp->free_addr = 0;
  /* invalidate the db until creation is complete */
  tmp->root4_addr = ADDR;
  tmp->root6_addr = ADDR;

  file = fopen(filepath, "wb");
  if (!file)
    goto fail0;
  if (fwrite(tmp, sizeof(db_header), 1, file) != 1)
    goto fail1;

  fclose(file);
  free(tmp);

  db = ipf_mount_db(filepath, 1);
  if (!db)
    return NULL;

  if (ipf_add_segment(db) != 1)
  {
    ipf_close_db(&db);
    return NULL;
  }
  /* set the root node */
  ipf_new_node(db, &(db->header->root4_addr));
  ipf_new_node(db, &(db->header->root6_addr));
  return db;
fail1:
  fclose(file);
fail0:
  free(tmp);
  return NULL;
}

void ipf_stat_db(IPF_DB * db, FILE * out)
{
  db_header * header = db->header;
  fprintf(out,"db_name    : %s\n", header->db_name);
  fprintf(out, "created    : %" PRId64 "\n", (int64_t)header->created);
  fprintf(out, "updated    : %" PRId64 "\n", (int64_t)header->updated);
  fprintf(out, "db_cur_size: %" PRIu64 "\n",
          (uint64_t)db->mmap_ctx.allocated_bytes);
  fprintf(out, "db_max_size: %" PRIu64 "\n",
          (uint64_t)db->mmap_ctx.reserved_bytes);
  fprintf(out, "seg_size   : %u\n", SEGMENT_SIZE(header->seg_mask));
  fprintf(out, "seg_count  : %u\n", (unsigned)header->seg_nb);
  fprintf(out, "freelist   : %08x\n", header->free_addr);
  fprintf(out, "rootnode4  : %08x\n", header->root4_addr);
  fprintf(out, "rootnode6  : %08x\n", header->root6_addr);
}

void ipf_close_db(IPF_DB ** db)
{
  (*db)->destructor(*db);
  *db = NULL;
}

static int ipf_give_back_tree(IPF_DB * db, uint32_t node_id)
{
  if ((node_id & ADDR))
  {
    node * _node = ipf_get_node(db, node_id);
    /* go to leaf */
    while (_node && (_node->raw0 & ADDR))
      _node = ipf_get_node(db, _node->raw0);
    if (!_node)
      return (-1); /* corruption */
    /* WARNING: leaf bit must be set to break any query in progress */
    if (_node->raw0)
      _node->raw0 = (_node->raw0 & LEAF) | db->header->free_addr;
    else
      _node->raw0 = LEAF | db->header->free_addr;
    db->header->free_addr = (node_id & ADDR);
  }
  return 0;
}

static ipf_response ipf_create_leaf(IPF_DB * db,
                                    ipf_cidr_address * cidr,
                                    uint32_t leaf_mask)
{
  node * n;
  int b, v = 0, ln = cidr->prefix - 1;
  uint32_t inherit = 0;

  if (ADDR_IS_V4MAPPED(cidr->addr))
  {
    b = V4MAPPED_1BIT;
    n = ipf_get_node(db, db->header->root4_addr);
  }
  else
  {
    b = 0;
    n = ipf_get_node(db, db->header->root6_addr);
  }

  for (; b < cidr->prefix; ++b)
  {
    int c = b >> 3;
    int d = 7 - b + (c << 3);
    v = (cidr->addr[c] >> d) & 0x1;
    //printf("%d ", v);

    /* corruption or failure */
    if (!n)
      return ipf_error;

    /* left branch */
    if (v == 0)
    {
      if (b == ln)
        break; /* make the leaf here */
      /* next node */
      if ((n->raw0 & ADDR))
        n = ipf_get_node(db, n->raw0);
      else if ((n->raw0 & leaf_mask))
        return LEAF_VALUE(leaf_mask); /* already exists */
      else
      {
        /* start a new branch ? */
        if (!inherit)
          inherit = n->raw0 & LEAF;
        /* make node */
        n = ipf_new_node(db, &(n->raw0));
        if (!n)
          return ipf_error;
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
        n = ipf_get_node(db, n->raw1);
      else if ((n->raw1 & leaf_mask))
        return LEAF_VALUE(leaf_mask); /* already exists */
      else
      {
        /* start a new branch ? */
        if (!inherit)
          inherit = n->raw1 & LEAF;
        /* make node */
        n = ipf_new_node(db, &(n->raw1));
        if (!n)
          return ipf_error;
        /* make new leaf inherit */
        n->raw0 = inherit;
        n->raw1 = inherit;
      }
    }
  }

  /* corruption or failure */
  if (!n)
    return ipf_error;

  /* make the leaf */
  if (ln < b)
  {
    if (ipf_give_back_tree(db, n->raw0) < 0 ||
            ipf_give_back_tree(db, n->raw1) < 0)
      return ipf_error;
    n->raw0 = leaf_mask;
    n->raw1 = leaf_mask;
  }
  else if (v == 0)
  {
    if (ipf_give_back_tree(db, n->raw0) < 0)
      return ipf_error;
    if ((n->raw0 & leaf_mask))
      return LEAF_VALUE(leaf_mask); /* already exists */
    n->raw0 = leaf_mask;
  }
  else
  {
    if (ipf_give_back_tree(db, n->raw1) < 0)
      return ipf_error;
    if ((n->raw1 & leaf_mask))
      return LEAF_VALUE(leaf_mask); /* already exists */
    n->raw1 = leaf_mask;
  }
  //printf("n %p = %d , %d\n", n, LEAF_VALUE(n->raw0), LEAF_VALUE(n->raw1));
  return ipf_not_found;
}

ipf_response ipf_insert_rule(IPF_DB * db,
                             ipf_cidr_address * cidr,
                             ipf_rule rule)
{
  switch (rule)
  {
  case ipf_rule_allow:
    return ipf_create_leaf(db, cidr, LEAF_ALLOW);
  case ipf_rule_deny:
    return ipf_create_leaf(db, cidr, LEAF_DENY);
  }
  return ipf_error;
}

void ipf_db_updated(IPF_DB * db)
{
  db->header->updated = time(NULL);
}

ipf_response ipf_query(IPF_DB * db, ipf_cidr_address * cidr)
{
  node * n;
  int b;

  if (ADDR_IS_V4MAPPED(cidr->addr))
  {
    b = V4MAPPED_1BIT;
    n = ipf_get_node(db, db->header->root4_addr);
  }
  else
  {
    b = 0;
    n = ipf_get_node(db, db->header->root6_addr);
  }

  for (; b < cidr->prefix; ++b)
  {
    int v;
    int c = b >> 3;
    int p = 7 - b + (c << 3);

    /* corruption or failure */
    if (!n)
      return ipf_error;

    v = (cidr->addr[c] >> p) & 0x1;

    /* WARNING: On deleting, this branch could be linked to free list.
     * For this case the leaf bit are set, so first check it to break.
     */
    if (v == 0)
    {
      /* left branch */
      if ((n->raw0 & LEAF))
        return LEAF_VALUE(n->raw0);
      else if ((n->raw0 & ADDR))
        n = ipf_get_node(db, n->raw0);
      else
        return ipf_not_found;
    }
    else
    {
      /* right branch */
      if ((n->raw1 & LEAF))
        return LEAF_VALUE(n->raw1);
      else if ((n->raw1 & ADDR))
        n = ipf_get_node(db, n->raw1);
      else
        return ipf_not_found;
    }
  }
  return ipf_not_found;
}

void ipf_purge_db(IPF_DB * db)
{
  unsigned s;
  node * seg;
  db_header * header = db->header;

  /* at least one segment should be initialized, else the db is invalid */
  if (db->cache.seg_nb < 1)
    return;

  /* reset the ip4 root node now */
  seg = ipf_get_node(db, header->root4_addr);
  seg->raw0 = 0;
  seg->raw1 = 0;
  /* reset the ip6 root node now */
  seg = ipf_get_node(db, header->root6_addr);
  seg->raw0 = 0;
  seg->raw1 = 0;
  /* reset freelist */
  header->free_addr = 0;

  /* clear all segments starting from last */
  seg = db->data + ((db->cache.seg_nb - 1) * db->cache.seg_sz);
  for (s = db->cache.seg_nb; s > 0 ; --s)
  {
    uint32_t addr = (s << 16);
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
    seg -= db->cache.seg_sz;
  }
  ipf_new_node(db, &(header->root4_addr));
  ipf_new_node(db, &(header->root6_addr));
}

static int ipf_read_db_header(db_header * header, FILE * file)
{
  char * addr;
  rewind(file);
  if (fread(header, sizeof(db_header), 1, file) != 1)
    return -(EIO);
  addr = (char*) header;
  /* check tag */
  if (memcmp(addr, ipf_dbtag, DBTAG_LEN) != 0)
    return -(EINVAL);
  addr += DBTAG_LEN;
  /* check endianness */
  if (memcmp(addr, &ipf_bom, sizeof (uint32_t)) != 0)
    return -(EINVAL);
  return 0;
}

IPF_DB * ipf_mount_db(const char * filepath, int rw)
{
  mmap_ctx mmap_ctx;
  char * addr;
  IPF_DB * db;
  db_header * file_header;
  FILE * file;

  /* return the already mounted db */
  if ((db = ipf_hold_mounted(filepath)))
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
  if (ipf_read_db_header(file_header, file) < 0)
    goto fail1;

  /* reserve the whole size */
  mmap_ctx.reserved_bytes = file_header->max_file_size;
  mmap_ctx.addr = ipf_mmap_reserve(&mmap_ctx.reserved_bytes);
  if (!mmap_ctx.addr)
    goto fail1;

  /* load the database */
  mmap_ctx.flag_rw = rw;
  mmap_ctx.file = file;
  if (ipf_mmap_database(&mmap_ctx) < 0)
    goto fail2;

  /* allocated size cannot be less than stated from file header */
  if (mmap_ctx.allocated_bytes < sizeof(db_header) +
          (file_header->seg_nb * SEGMENT_SIZE(file_header->seg_mask) * sizeof (node)))
    goto fail3;

  addr = (char*) mmap_ctx.addr;

  db = (IPF_DB*) malloc(sizeof (IPF_DB));
  if (!db)
    goto fail2;
  /* keep in cache the older known state, therefore from file header */
  db->cache.seg_nb = file_header->seg_nb;
  db->cache.seg_sz = SEGMENT_SIZE(file_header->seg_mask);
  free(file_header);

  /* init the database */
  db->header = (db_header*) addr;
  db->destructor = ipf_free_mounted_db;
  db->mmap_ctx = mmap_ctx;
  db->data = (node *) (addr + sizeof (db_header));

  /* register the mounted db */
  ipf_register_mounted(filepath, db);
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

static int ipf_dec_to_num(const char *str)
{
  int val = 0;
  while (*str)
  {
    if (*str < '0' || *str > '9')
      break;
    val *= 10;
    val += ((*str) - '0');
    str++;
  }
  return val;
}

static int ipf_u8_to_dec(char * str, unsigned char u)
{
  int d, s = 0, len = 0;
  static const char g[10] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  };

  for (d = 100; d > 1; d /= 10)
  {
    int c = (u - s) / d;
    s += c * d;
    if (s)
    {
      str[len++] = g[c];
    }
  }
  str[len++] = g[(u - s)];
  return len;
}

static int ipf_hex_to_num(const char *str)
{
  int val = 0;
  while (*str)
  {
    if (*str >= '0' && *str <= '9')
      val = (val << 4) + (*str - '0');
    else if (*str >= 'A' && *str <= 'F')
      val = (val << 4) + (*str - 'A' + 10);
    else if (*str >= 'a' && *str <= 'f')
      val = (val << 4) + (*str - 'a' + 10);
    else
      break;
    ++str;
  }
  return val;
}

static int ipf_u16_to_hex(char * str, uint16_t u)
{
  int d, s = 0, len = 0;
  static const char g[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  };

  for (d = 12; d > 0; d -= 4)
  {
    int c = 0xf & (u >> d);
    s += c;
    if (s)
    {
      str[len++] = g[c];
    }
  }
  str[len++] = g[(0xf & u)];
  return len;
}

int ipf_create_cidr_address_2(ipf_cidr_address * cidr,
                              const char * addr_str,
                              int prefix)
{
  int i, len;
  const char * p;

  len = strlen(addr_str);
  p = addr_str + len;
  while (*(--p) != '.' && p > addr_str);

  /* parse ip4 address string */
  if (p > addr_str)
  {
    while (*(--p) != ':' && p > addr_str);
    if (*p == ':')
      ++p;
    else
      prefix += V4MAPPED_1BIT;

    memcpy(cidr->addr, ipf_addr4_init, IPF_ADDR_SZ);
    /* front to back */
    i = 12;
    for (;;)
    {
      int val = ipf_dec_to_num(p);
      cidr->addr[i] = val & 0xff;
      ++i;
      while (*(++p) != '.' && *p != '\0');
      if (*p == '\0' || i >= IPF_ADDR_SZ)
        break;
      ++p;
    }
    if (i < IPF_ADDR_SZ)
      return -(EINVAL);
  }
  /* parse ip6 address string */
  else
  {
    memcpy(cidr->addr, ipf_addr6_init, IPF_ADDR_SZ);
    /* front to back */
    i = 0;
    for (;;)
    {
      if (*p == ':')
        break;
      int val = ipf_hex_to_num(p);
      cidr->addr[i] = (val >> 8) & 0xff;
      cidr->addr[i+1] = val & 0xff;
      i += 2;
      while (*(++p) != ':' && *p != '\0');
      if (*p == '\0' || i >= IPF_ADDR_SZ)
        break;
      ++p;
    }
    /* back to front */
    if (i < IPF_ADDR_SZ)
    {
      const char * ps = p;
      p = addr_str + len - 1;
      while (*p != ':') --p;
      i = IPF_ADDR_SZ - 2;
      for (;;)
      {
        int val = ipf_hex_to_num(p + 1);
        cidr->addr[i] = (val >> 8) & 0xff;
        cidr->addr[i+1] = val & 0xff;
        i -= 2;
        while (*(--p) != ':' && p > addr_str);
        if (*(p + 1) == ':' || p == addr_str)
          break;
      }
      /* validate */
      if (p > ps)
        return -(EINVAL);
    }
  }

  cidr->prefix = prefix;
  return 0;
}

int ipf_create_cidr_address(ipf_cidr_address * cidr,
                            const char * cidr_str)
{
  int prefix;
  const char * p;

  p = cidr_str + strlen(cidr_str) - 1;
  while (*(--p) != '/' && p > cidr_str);
  if (p == cidr_str)
    return -(EINVAL);
  prefix = ipf_dec_to_num(p + 1);
  if (prefix < 0 || prefix > (8 * IPF_ADDR_SZ))
    return -(EINVAL);
  return ipf_create_cidr_address_2(cidr, cidr_str, prefix);
}

void ipf_init_address_ipv4_mapped(ipf_cidr_address * cidr)
{
  memcpy(cidr->addr, ipf_addr4_init, IPF_ADDR_SZ);
  cidr->prefix = (8 * IPF_ADDR_SZ);
}

static void ipf_set_bit(unsigned char * addr, int bit_no, int v)
{
  if (bit_no > 0)
  {
    int p, b;
    p = (bit_no - 1) / 8;
    b = bit_no - 8 * p;
    if (v)
      /* on */
      addr[p] |= (1 << (8 - b));
    else
      /* off */
      addr[p] &= (0xff - (1 << (8 - b)));
  }
}

static int ipf_print_ip4(char * buf, ipf_cidr_address * cidr)
{
  int len = 0;

  len += ipf_u8_to_dec(buf, cidr->addr[IPF_ADDR_SZ - 4]);
  buf[len++] = '.';
  len += ipf_u8_to_dec(buf + len, cidr->addr[IPF_ADDR_SZ - 3]);
  buf[len++] = '.';
  len += ipf_u8_to_dec(buf + len, cidr->addr[IPF_ADDR_SZ - 2]);
  buf[len++] = '.';
  len += ipf_u8_to_dec(buf + len, cidr->addr[IPF_ADDR_SZ - 1]);

  buf[len++] = '/';
  len += ipf_u8_to_dec(buf + len, cidr->prefix - V4MAPPED_1BIT);
  buf[len] = '\0';
  return len;
}

static int ipf_visit_node4(IPF_DB * db, FILE * out,
                           ipf_cidr_address cidr,
                           uint32_t node_id)
{
  node * _node;

  _node = ipf_get_node(db, node_id);
  if (!_node)
    return (-1); /* corruption */

  /* processing next bit */
  cidr.prefix++;

  /* visit left (0) */
  if ((_node->raw0 & LEAF))
  {
    char buf[24];
    ipf_set_bit(cidr.addr, cidr.prefix, 0);
    ipf_print_ip4(buf, &cidr);
    fputs(((_node->raw0 & LEAF) == LEAF_ALLOW ? "ALLOW " : "DENY "), out);
    fputs(buf, out);
    if (fputc('\n', out) < 1)
      return (-1);
  }
  else if ((_node->raw0 & ADDR))
  {
    ipf_set_bit(cidr.addr, cidr.prefix, 0);
    if (ipf_visit_node4(db, out, cidr, _node->raw0) < 0)
      return (-1);
  }

  /* visit right (1) */
  if ((_node->raw1 & LEAF))
  {
    char buf[24];
    ipf_set_bit(cidr.addr, cidr.prefix, 1);
    ipf_print_ip4(buf, &cidr);
    fputs(((_node->raw1 & LEAF) == LEAF_ALLOW ? "ALLOW " : "DENY "), out);
    fputs(buf, out);
    if (fputc('\n', out) < 1)
      return (-1);
  }
  else if ((_node->raw1 & ADDR))
  {
    ipf_set_bit(cidr.addr, cidr.prefix, 1);
    if (ipf_visit_node4(db, out, cidr, _node->raw1) < 0)
      return (-1);
  }

  return 0;
}

static int ipf_print_ip6(char * buf, ipf_cidr_address * cidr)
{
  int i = 0, cp = -1, cl = 0, len = 0;

  do
  {
    int j = i;
    while (j < (IPF_ADDR_SZ - 1) && cidr->addr[j] == 0 && cidr->addr[j+1] == 0)
      j += 2;
    if ((j - i) > cl)
    {
      cp = i;
      cl = j - i;
    }
    i = j + 2;
  } while (i < IPF_ADDR_SZ);

  i = 0;
  do
  {
    if (i == cp)
    {
      i += cl;
      buf[len++] = ':';
      if (i >= IPF_ADDR_SZ)
        buf[len++] = ':';
    }
    else
    {
      uint16_t s;
      s = cidr->addr[i] << 8;
      s += cidr->addr[i+1];
      if (i)
        buf[len++] = ':';
      len += ipf_u16_to_hex(buf + len, s);
      i += 2;
    }
  } while (i < IPF_ADDR_SZ);

  buf[len++] = '/';
  len += ipf_u8_to_dec(buf + len, cidr->prefix);
  buf[len] = '\0';
  return len;
}

static int ipf_visit_node6(IPF_DB * db, FILE * out,
                           ipf_cidr_address cidr,
                           uint32_t node_id)
{
  node * _node;

  _node = ipf_get_node(db, node_id);
  if (!_node)
    return (-1); /* corruption */

  /* processing next bit */
  cidr.prefix++;

  /* visit left (0) */
  if ((_node->raw0 & LEAF))
  {
    char buf[48];
    ipf_set_bit(cidr.addr, cidr.prefix, 0);
    ipf_print_ip6(buf, &cidr);
    fputs(((_node->raw0 & LEAF) == LEAF_DENY ? "DENY " : "ALLOW "), out);
    fputs(buf, out);
    if (fputc('\n', out) < 1)
      return (-1);
  }
  else if ((_node->raw0 & ADDR))
  {
    ipf_set_bit(cidr.addr, cidr.prefix, 0);
    if (ipf_visit_node6(db, out, cidr, _node->raw0) < 0)
      return (-1);
  }

  /* visit right (1) */
  if ((_node->raw1 & LEAF))
  {
    char buf[48];
    ipf_set_bit(cidr.addr, cidr.prefix, 1);
    ipf_print_ip6(buf, &cidr);
    fputs(((_node->raw1 & LEAF) == LEAF_DENY ? "DENY " : "ALLOW "), out);
    fputs(buf, out);
    if (fputc('\n', out) < 1)
      return (-1);
  }
  else if ((_node->raw1 & ADDR))
  {
    ipf_set_bit(cidr.addr, cidr.prefix, 1);
    if (ipf_visit_node6(db, out, cidr, _node->raw1) < 0)
      return (-1);
  }

  return 0;
}

int ipf_export_db(IPF_DB * db, FILE * out)
{
  int r = 0;
  ipf_cidr_address cidr;

  memcpy(cidr.addr, ipf_addr4_init, IPF_ADDR_SZ);
  cidr.prefix = V4MAPPED_1BIT;
  r |= ipf_visit_node4(db, out, cidr, db->header->root4_addr);

  memcpy(cidr.addr, ipf_addr6_init, IPF_ADDR_SZ);
  cidr.prefix = 0;
  r |= ipf_visit_node6(db, out, cidr, db->header->root6_addr);
  return r;
}
