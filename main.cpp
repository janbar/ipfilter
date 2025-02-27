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

#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <string>
#include <algorithm> // std::find
#include <chrono>

#include <string.h>
#include <unistd.h>

#include "tokenizer.h"
#include "db.h"

#define LASTERROR errno
#define ERRNO_INTR EINTR
#define FLUSHOUT() fflush(stdout);
#define PRINT(a) fprintf(stdout, a)
#define PRINT1(a,b) fprintf(stdout, a, b)
#define PRINT2(a,b,c) fprintf(stdout, a, b, c)
#define PERROR(a) fprintf(stderr, a)
#define PERROR1(a,b) fprintf(stderr, a, b)
#define PERROR2(a,b,c) fprintf(stderr, a, b, c)

static const char * getCmd(char **begin, char **end, const std::string& option);
static const char * getCmdOption(char **begin, char **end, const std::string& option);
static bool parseCommand(const std::string& line, bool& failed);
static void readInStream();

int load_cidr_file(IPF_DB * db, const char * filepath, ipf_rule rule);
int load_rule_file(IPF_DB * db, const char * filepath);

static IPF_DB * g_db = nullptr;
static bool g_tainted = false;  /* need write back */

/*
 * the main function
 */
int main(int argc, char** argv)
{
  int ret = 0;
  char** end = argv + argc;
  char** cur = argv;

  if (getCmd(cur, end, "--help") || getCmd(cur, end, "-h"))
  {
    PRINT("  -s                           Do not print the banner\n");
    PRINT("  -d <database file path>      Mount the database\n");
    PRINT("  -c \"<command>\" ...           Execute all commands to follow and exit\n");
    PRINT("  --help | -h                  Show help and exit\n\n");
    return EXIT_SUCCESS;
  }
  /* print header unless silence is requested */
  if (!getCmd(cur, end, "-s"))
  {
    PRINT1("IPFILTER CLI (%s), Copyright (C) 2023 Jean-Luc Barriere\n", ipf_db_format());
#ifdef LIBVERSION
    PRINT("Version " LIBVERSION " compiled on " __DATE__ " at " __TIME__ "\n");
#endif
  }
  /* processing all others arguments */
  while (++cur < end)
  {
    if (strcmp(*cur, "-d") == 0)
    {
      if (++cur >= end)
      {
        PERROR("Error: Missing argument\n");
        return EXIT_FAILURE;
      }
      if (g_db)
        ipf_close_db(&g_db);
      g_db = ipf_mount_db(*cur, 1);
      if (g_db == nullptr)
      {
        PERROR1("Error: Database not mounted (%d)\n", LASTERROR);
        return EXIT_FAILURE;
      }
    }
    else if (strcmp(*cur, "-c") == 0)
    {
      /* the arguments to follow are commands to execute */
      bool failed = false;
      /* break on first failure */
      while (!failed && ++cur < end)
      {
        if (!parseCommand(*cur, failed))
          break;
      }
      /* close database gracefully and exit */
      if (g_db)
      {
        if (g_tainted)
          ret = ipf_flush_db(g_db);
        ipf_close_db(&g_db);
      }
      return (failed || ret != 0 ? EXIT_FAILURE : EXIT_SUCCESS);
    }
  }

  /* start interactive mode */
  readInStream();

  if (g_db)
  {
    if (g_tainted)
      ret = ipf_flush_db(g_db);
    ipf_close_db(&g_db);
  }

  return (ret != 0 ? EXIT_FAILURE : EXIT_SUCCESS);
}

static const char * getCmd(char **begin, char **end, const std::string& option)
{
  char **itr = std::find(begin, end, option);
  if (itr != end)
  {
    return *itr;
  }
  return NULL;
}

static const char * getCmdOption(char **begin, char **end, const std::string& option)
{
  for (char** it = begin; it != end; ++it)
  {
    if (strncmp(*it, option.c_str(), option.length()) == 0 && ((it + 1) != end))
      return *(it + 1);
  }
  return NULL;
}

std::string& upstr(std::string& str)
{
  std::string::iterator c = str.begin();
  while (c != str.end())
  {
    *c = toupper(*c);
    ++c;
  }
  return str;
}

static double timestamp()
{
  static auto _ts_init = std::chrono::system_clock::now();
  auto ts = std::chrono::system_clock::now();
  std::chrono::duration<double> diff = ts - _ts_init;
  return diff.count();
}

static bool parseCommand(const std::string& line, bool& failed)
{
  bool failure = true;
  std::vector<std::string> tokens;
  tokenize(line, " ", "\"", tokens, true);
  std::vector<std::string>::const_iterator it = tokens.begin();
  if (it != tokens.end())
  {
    std::string token(*it);
    upstr(token);

    if (token == "EXIT")
    {
      failed = false;
      return false;
    }
    else if (token == "")
    {
      failure = false;
    }
    else if (token == "HELP")
    {
      PRINT("EXIT\n");
      PRINT("  Exit from CLI.\n\n");
      PRINT("CREATE {file path} [seg size]\n");
      PRINT("  Create new database. The default seg size is 256.\n\n");
      PRINT("SETNAME {name}\n");
      PRINT("  Rename the database.\n\n");
      PRINT("MOUNT {file path}\n");
      PRINT("  Mount database from binary db file.\n\n");
      PRINT("MOUNT READONLY {file path}\n");
      PRINT("  Mount read only database from binary db file.\n\n");
      PRINT("STATUS\n");
      PRINT("  Show statistics of the database.\n\n");
      PRINT("ALLOW {CIDR}\n");
      PRINT("  Insert a rule allow CIDR (d.d.d.d/d or x::x/d).\n\n");
      PRINT("DENY {CIDR}\n");
      PRINT("  Insert a rule deny CIDR (d.d.d.d/d or x::x/d).\n\n");
      PRINT("TEST {CIDR}\n");
      PRINT("  Test matching for CIDR (d.d.d.d/d or x::x/d).\n\n");
      PRINT("LOAD ALLOW|DENY {file path}\n");
      PRINT("  Fill database with contents of CIDR file.\n\n");
      PRINT("LOAD RULE {file path}\n");
      PRINT("  Fill database with contents of rules file.\n\n");
      PRINT("EXPORT [file path]\n");
      PRINT("  Export the database rules to output or file.\n\n");
      PRINT("PURGE FORCE\n");
      PRINT("  Clear the database.\n\n");
      PRINT("SYNC\n");
      PRINT("  Force write back.\n\n");
      PRINT("Type HELP to print this help.\n\n");
      failure = false;
    }
    else if (token == "CREATE")
    {
      unsigned sz = 0;
      std::string filepath;
      if (++it != tokens.end())
        filepath.assign(*it);
      if (++it != tokens.end())
        sscanf((*it).c_str(), "%d", &sz);
      if (g_db)
        ipf_close_db(&g_db);
      g_db = ipf_create_db(filepath.c_str(), "noname", sz);
      if (g_db)
      {
        PERROR("Succeeded\n");
        g_tainted = true;
        failure = false;
      }
      else
        PERROR("Failed\n");
    }
    else if (token == "SETNAME")
    {
      if (++it != tokens.end() && g_db)
      {
        int r = ipf_rename_db(g_db, it->c_str());
        if (r)
          PERROR1("Error: %d\n", r);
        else
        {
          g_tainted = true;
          failure = false;
        }
      }
      else
        PERROR("Error: Invalid context\n");
    }
    else if (token == "STATUS")
    {
      if (g_db)
      {
        ipf_stat_db(g_db, stdout);
        failure = false;
      }
      else
        PERROR("Error: Invalid context\n");
    }
    else if (token == "EXPORT")
    {
      if (g_db)
      {
        std::string filepath;
        if (++it != tokens.end())
        {
          filepath.assign(*it);
          FILE * out = ::fopen(filepath.c_str(), "w");
          if (out)
          {
            if (ipf_export_db(g_db, out) < 0)
              PERROR1("Error: Export failed (%d)\n", LASTERROR);
            else
            {
              PERROR("Succeeded\n");
              failure = false;
            }
            fclose(out);
          }
          else
            PERROR1("Error: Create file failed (%d)\n", LASTERROR);
        }
        else
        {
          if (ipf_export_db(g_db, stdout) < 0)
            PERROR1("Error: Export failed (%d)\n", LASTERROR);
        }
      }
      else
        PERROR("Error: Invalid context\n");
    }
    else if (token == "PURGE")
    {
      if (++it != tokens.end() && g_db)
      {
        std::string param(*it);
        upstr(param);
        if (param == "FORCE")
        {
          int r = ipf_purge_db(g_db);
          if (r)
            PERROR1("Error: %d\n", r);
          else
          {
            g_tainted = true;
            failure = false;
            PERROR("Database has been purged\n");
          }
        }
      }
      else
        PERROR("Error: Invalid context\n");
    }
    else if (token == "SYNC")
    {
      if (g_db)
      {
        if (g_tainted)
        {
          g_tainted = false;
          int r = ipf_flush_db(g_db);
          if (r)
            PERROR1("Error: %d\n", r);
          else
            failure = false;
        }
      }
      else
        PERROR("Error: Invalid context\n");
    }
    else if (token == "TEST")
    {
      if (++it != tokens.end() && g_db)
      {
        std::string param(*it);
        ipf_cidr_address cidr;
        if (ipf_create_cidr_address(&cidr, param.c_str()) == 0)
        {
          double t0 = timestamp();
          int r = ipf_query(g_db, &cidr);
          double d = timestamp() - t0;
          failure = false;
          switch (r)
          {
          case ipf_not_found:
            PRINT1("[ empty ] elap: %f sec\n", d);
            break;
          case ipf_allow:
            PRINT1("[ allow ] elap: %f sec\n", d);
            break;
          case ipf_deny:
            PRINT1("[ deny  ] elap: %f sec\n", d);
            break;
          case ipf_error:
            PERROR1("Error: %d\n", LASTERROR);
            failure = true;
            break;
          }
        }
        else
          PERROR("Error: Invalid argument\n");
      }
      else
        PERROR("Error: Invalid context\n");
    }
    else if (token == "ALLOW")
    {
      if (++it != tokens.end() && g_db)
      {
        std::string param(*it);
        ipf_cidr_address cidr;
        if (ipf_create_cidr_address(&cidr, param.c_str()) == 0)
        {
          double t0 = timestamp();
          ipf_response r = ipf_insert_rule(g_db, &cidr, ipf_rule_allow);
          double d = timestamp() - t0;
          if (r == ipf_allow)
          {
            PRINT("Already exists\n");
            failure = false;
          }
          else if (r == ipf_not_found)
          {
            PRINT1("Inserted, elap: %f sec\n", d);
            g_tainted = true;
            failure = false;
          }
          else if (ipf_mode_rw(g_db))
            PERROR1("Error: %d\n", LASTERROR);
          else
            PERROR1("Error: %d\n", -(EPERM));
        }
        else
          PERROR("Error: Invalid argument\n");
      }
      else
        PERROR("Error: Invalid context\n");
    }
    else if (token == "DENY")
    {
      if (++it != tokens.end() && g_db)
      {
        std::string param(*it);
        ipf_cidr_address cidr;
        if (ipf_create_cidr_address(&cidr, param.c_str()) == 0)
        {
          double t0 = timestamp();
          ipf_response r = ipf_insert_rule(g_db, &cidr, ipf_rule_deny);
          double d = timestamp() - t0;
          if (r == ipf_deny)
          {
            PRINT("Entry already exists\n");
            failure = false;
          }
          else if (r == ipf_not_found)
          {
            PRINT1("Inserted, elap: %f sec\n", d);
            g_tainted = true;
            failure = false;
          }
          else if (ipf_mode_rw(g_db))
            PERROR1("Error: %d\n", LASTERROR);
          else
            PERROR1("Error: %d\n", -(EPERM));
        }
        else
          PERROR("Error: Invalid argument\n");
      }
      else
        PERROR("Error: Invalid context\n");
    }
    else if (token == "LOAD")
    {
      if (++it != tokens.end() && g_db)
      {
        std::string rule(*it);
        if (++it != tokens.end())
        {
          int r = (-1);
          double d;
          upstr(rule);
          std::string param(*it);
          if (rule == "ALLOW")
          {
            d = timestamp();
            r = load_cidr_file(g_db, param.c_str(), ipf_rule_allow);
            d = timestamp() - d;
          }
          else if (rule == "DENY")
          {
            d = timestamp();
            r = load_cidr_file(g_db, param.c_str(), ipf_rule_deny);
            d = timestamp() - d;
          }
          else if (rule == "RULE")
          {
            d = timestamp();
            r = load_rule_file(g_db, param.c_str());
            d = timestamp() - d;
          }
          if (r == 0)
          {
            PRINT1("Loaded, elap: %f sec\n", d);
            failure = false;
          }
          else
            PERROR1("Error: %d\n", r);
        }
        else
          PERROR("Error: Missing argmuent\n");
      }
      else
        PERROR("Error: Invalid context\n");
    }
    else if (token == "MOUNT")
    {
      if (++it != tokens.end())
      {
        std::string param(*it);
        upstr(param);
        if (param == "READONLY")
        {
          if (++it != tokens.end())
          {
            param.assign(*it);
            if (g_db)
              ipf_close_db(&g_db);
            g_db = ipf_mount_db(param.c_str(), 0);
            if (g_db)
            {
              PRINT("Mounted read only\n");
              failure = false;
            }
            else
              PERROR1("Error: %d\n", LASTERROR);
          }
          else
            PERROR("Error: Missing argument\n");
        }
        else
        {
          param.assign(*it);
          if (g_db)
            ipf_close_db(&g_db);
          g_db = ipf_mount_db(param.c_str(), 1);
          if (g_db)
          {
            PRINT("Mounted\n");
            failure = false;
          }
          else
            PERROR1("Error: %d\n", LASTERROR);
        }
      }
      else
        PERROR("Error: Invalid argument\n");
    }
    else
    {
      PERROR("Error: Command invalid\n");
    }
  }
  failed = failure;
  return true;
}

static void prompt() {
  if (g_db)
    PRINT1("%s >>> ", ipf_db_name(g_db));
  else
    PRINT(">>> ");
  FLUSHOUT();
}

static void readInStream()
{
  static int maxlen = 1023;
  char* buf = new char[maxlen + 1];
  size_t len = 0;
  bool run = true;
#ifndef __WINDOWS__
  fd_set fds;
#endif

  prompt();

  while (run)
  {
#ifndef __WINDOWS__
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    int r = select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
    if (r > 0 && FD_ISSET(STDIN_FILENO, &fds))
#endif
    {
      int chr;
      while (run && (chr = getchar()) != EOF)
      {
        if (chr != '\n')
        {
          if (len < maxlen)
            buf[len++] = (char) chr;
        }
        else
        {
          buf[len] = '\0';
          bool failed;
          if ((run = parseCommand(buf, failed)))
          {
            len = 0;
            prompt();
          }
        }
      }
    }
#ifndef __WINDOWS__
    else if (r < 0)
    {
      if (LASTERROR == ERRNO_INTR)
        continue;
      else
        break;
    }
#endif
  }

  delete[] buf;
}

/*****************************************************************************/
/* Macros                                                                    */
/*****************************************************************************/

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

int load_cidr_file(IPF_DB * db, const char * filepath, ipf_rule rule)
{
  FILE* file = fopen(filepath, "r");
  char line[256];
  unsigned r = 0, l = 0, c = 0;
  if (!file)
    return -(ENOENT);
  while ((r = _readln(line, sizeof (line) - 1, file)))
  {
    ++l; /* for debug */
    /* read line must be terminated by CTRL+N */
    if (line[r - 1] != '\n')
      break;
    /* convert to string ending with zero */
    line[r - 1] = '\0';
    /* parse line */
    std::vector<std::string> tokens;
    tokenize(line, " ", "", tokens, true);
    std::vector<std::string>::const_iterator it = tokens.begin();
    if (it == tokens.end())
      continue;
    std::string token(*it);
    /* discard comment or empty line */
    if (token.at(0) == '#')
      continue;
    /* parse CIDR address */
    ipf_cidr_address adr;
    if (ipf_create_cidr_address(&adr, token.c_str()) < 0)
      break;
    if (ipf_insert_rule(db, &adr, rule) == ipf_error)
      break;
    if (!(c & 0xff))
    {
      PRINT(".");
      FLUSHOUT();
    }
    ++c;
  }
  PRINT1(" %u\n", c);
  fclose(file);
  if (r != 0)
  {
    line[r] = '\0';
    PERROR2("ERROR: Insertion failed on '%s' at line %d.\n", line, l);
    return -(EINVAL);
  }
  if (c > 0 || g_tainted)
  {
    g_tainted = false;
    return ipf_flush_db(db);
  }
  return 0;
}

int load_rule_file(IPF_DB * db, const char * filepath)
{
  FILE* file = fopen(filepath, "r");
  char line[256];
  unsigned r = 0, l = 0, c = 0;
  if (!file)
    return -(ENOENT);
  while ((r = _readln(line, sizeof (line) - 1, file)))
  {
    ++l; /* for debug */
    /* read line must be terminated by CTRL+N */
    if (line[r - 1] != '\n')
      break;
    /* convert to string ending with zero */
    line[r - 1] = '\0';
    /* parse line */
    std::vector<std::string> tokens;
    tokenize(line, " ", "", tokens, true);
    std::vector<std::string>::const_iterator it = tokens.begin();
    if (it == tokens.end())
      continue;
    std::string token(*it);
    /* discard comment or empty line */
    if (token.at(0) == '#')
      continue;
    /* parse RULE */
    ipf_rule rule;
    upstr(token);
    if (token == "ALLOW")
      rule = ipf_rule_allow;
    else if (token == "DENY")
      rule = ipf_rule_deny;
    else
      break;
    /* parse CIDR address */
    if (it == tokens.end())
      break;
    token.assign(*(++it));
    ipf_cidr_address adr;
    if (ipf_create_cidr_address(&adr, token.c_str()) < 0)
      break;
    if (ipf_insert_rule(db, &adr, rule) == ipf_error)
      break;
    if (!(c & 0xff))
    {
      PRINT(".");
      FLUSHOUT();
    }
    ++c;
  }
  PRINT1(" %u\n", c);
  fclose(file);
  if (r != 0)
  {
    line[r] = '\0';
    PERROR2("ERROR: Insertion failed on '%s' at line %d.\n", line, l);
    return -(EINVAL);
  }
  if (c > 0 || g_tainted)
  {
    g_tainted = false;
    return ipf_flush_db(db);
  }
  return 0;
}
