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
static void readInStream();

int load_cidr_file(DB * db, const char * filepath, db_rule rule);

static DB * g_db = nullptr;

/*
 * the main function
 */
int main(int argc, char** argv)
{
  int ret = 0;

  if (getCmd(argv, argv + argc, "--help") || getCmd(argv, argv + argc, "-h"))
  {
    PRINT("\n  --help | -h\n\n");
    PRINT("  Print the command usage.\n\n");
    return EXIT_SUCCESS;
  }

  PRINT1("IPFILTER CLI (%s), Copyright (C) 2023 Jean-Luc Barriere\n", db_format());

  readInStream();

  if (g_db)
    close_db(&g_db);

  return ret;
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
    if (strncmp(*it, option.c_str(), option.length()) == 0 && (*it)[option.length()] == '=')
      return &((*it)[option.length() + 1]);
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

static bool parseCommand(const std::string& line)
{
  std::vector<std::string> tokens;
  tokenize(line, " ", tokens, true);
  std::vector<std::string>::const_iterator it = tokens.begin();
  if (it != tokens.end())
  {
    std::string token(*it);
    upstr(token);

    if (token == "EXIT")
      return false;
    else if (token == "")
    {}
    else if (token == "HELP")
    {
      PRINT("EXIT                          Exit from CLI\n");
      PRINT("CREATE $1 [$2]                Create new database\n");
      PRINT("  $1 : file path (no space)\n");
      PRINT("  $2 : segment size from 256 to 65536. The default is 256.\n");
      PRINT("SETNAME $name                 Rename the database (no space)\n");
      PRINT("MOUNT $1                      Mount database from binary db file\n");
      PRINT("  $1 : file path (no space)\n");
      PRINT("STATUS                        Show statistics of the database\n");
      PRINT("ALLOW $CIDR                   Allow CIDR (n.n.n.n/n)\n");
      PRINT("DENY $CIDR                    Deny CIDR (n.n.n.n/n)\n");
      PRINT("TEST $CIDR                    Test CIDR matching (n.n.n.n/n)\n");
      PRINT("LOAD ALLOW|DENY $1            Fill database with CIDR file\n");
      PRINT("  $1 : file path (no space)\n");
      PRINT("PURGE FORCE                   Purge the database\n");
      PRINT("HELP                          Print this help\n");
      PRINT("\n");
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
        close_db(&g_db);
      g_db = create_db(filepath.c_str(), "noname", sz);
      if (g_db)
        PERROR("Succeeded\n");
      else
        PERROR("Failed\n");
    }
    else if (token == "SETNAME")
    {
      if (++it != tokens.end() && g_db)
        rename_db(g_db, it->c_str());
    }
    else if (token == "STATUS")
    {
      if (g_db)
        stat_db(g_db);
    }
    else if (token == "PURGE")
    {
      if (++it != tokens.end() && g_db)
      {
        std::string param(*it);
        upstr(param);
        if (param == "FORCE")
        {
          purge_db(g_db);
          PERROR("Database has been purged\n");
        }
      }
      else
        PERROR("Invalid context\n");
    }
    else if (token == "TEST")
    {
      if (++it != tokens.end() && g_db)
      {
        std::string param(*it);
        cidr_address cidr;
        if (create_cidr_address(&cidr, param.c_str()) == 0)
        {
          double t0 = timestamp();
          int r = find_record(g_db, &cidr);
          double d = timestamp() - t0;
          switch (r)
          {
          case db_not_found:
            PRINT1("[ empty ] elap: %f sec\n", d);
            break;
          case db_allow:
            PRINT1("[ allow ] elap: %f sec\n", d);
            break;
          case db_deny:
            PRINT1("[ deny  ] elap: %f sec\n", d);
            break;
          case db_error:
            PERROR1("Error: %d\n", LASTERROR);
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
        cidr_address cidr;
        if (create_cidr_address(&cidr, param.c_str()) == 0)
        {
          double t0 = timestamp();
          db_response r = insert_cidr(g_db, &cidr, rule_allow);
          double d = timestamp() - t0;
          if (r == db_allow)
            PRINT("Already exists\n");
          else if (r == db_not_found)
            PRINT1("Inserted, elap: %f sec\n", d);
          else
            PERROR1("Error: %d\n", LASTERROR);
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
        cidr_address cidr;
        if (create_cidr_address(&cidr, param.c_str()) == 0)
        {
          double t0 = timestamp();
          db_response r = insert_cidr(g_db, &cidr, rule_deny);
          double d = timestamp() - t0;
          if (r == db_deny)
            PRINT("Entry already exists\n");
          else if (r == db_not_found)
            PRINT1("Inserted, elap: %f sec\n", d);
          else
            PERROR1("Error: %d\n", LASTERROR);
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
            r = load_cidr_file(g_db, param.c_str(), rule_allow);
            d = timestamp() - d;
          }
          else if (rule == "DENY")
          {
            d = timestamp();
            r = load_cidr_file(g_db, param.c_str(), rule_deny);
            d = timestamp() - d;
          }
          if (r == 0)
            PRINT1("Loaded, elap: %f sec\n", d);
          else
            PERROR1("Error: %d\n", r);
        }
      }
      else
        PERROR("Error: Invalid context\n");
    }
    else if (token == "MOUNT")
    {
      if (++it != tokens.end())
      {
        std::string param(*it);
        if (g_db)
          close_db(&g_db);
        g_db = mount_db(param.c_str(), 1);
        if (g_db)
          PRINT("Mounted\n");
        else
          PERROR1("Error: %d\n", LASTERROR);
      }
      else
        PERROR("Error: Invalid argument\n");
    }
    else
    {
      PERROR("Error: Command invalid\n");
    }
  }
  return true;
}

static void prompt() {
  if (g_db)
    PRINT1("%s >>> ", db_name(g_db));
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
          if ((run = parseCommand(buf)))
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

int load_cidr_file(DB * db, const char * filepath, db_rule rule)
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
    tokenize(line, " ", tokens, true);
    std::vector<std::string>::const_iterator it = tokens.begin();
    if (it == tokens.end())
      continue;
    std::string token(*it);
    /* discard comment or empty line */
    if (token.at(0) == '#')
      continue;
    /* parse CIDR address */
    cidr_address adr;
    if (create_cidr_address(&adr, token.c_str()) < 0)
      break;
    if (insert_cidr(db, &adr, rule) == db_error)
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
  if (c > 0)
    db_updated(db);
  if (r == 0)
    return 0;
  line[r] = '\0';
  PERROR2("ERROR: Insertion failed on '%s' at line %d.\n", line, l);
  return -(EINVAL);
}
