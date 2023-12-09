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
#define PERROR(a) fprintf(stderr, a)
#define PERROR1(a,b) fprintf(stderr, a, b)

static const char * getCmd(char **begin, char **end, const std::string& option);
static const char * getCmdOption(char **begin, char **end, const std::string& option);
static void readInStream();

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
      PRINT("CREATE {1} [2]                Create new database\n");
      PRINT("  {1}: file path (no space)\n");
      PRINT("  [2]: segment size (default 512)\n");
      PRINT("SETNAME {name}                Rename the database (no space)\n");
      PRINT("MOUNT {1}                     Mount database from binary db file\n");
      PRINT("  {1}: file path (no space)\n");
      PRINT("STATUS                        Show statistics of the database\n");
      PRINT("INSERT {CIDR}                 Add new record CIDR (n.n.n.n/n)\n");
      PRINT("TEST {CIDR}                   Test CIDR matching (n.n.n.n/n)\n");
      PRINT("LOAD {1}                      Fill database with content of CIDR file\n");
      PRINT("  {1}: file path (no space)\n");
      PRINT("HELP                          Print this help\n");
      PRINT("\n");
    }
    else if (token == "CREATE")
    {
      uint16_t sz = 0;
      std::string filepath;
      if (++it != tokens.end())
        filepath.assign(*it);
      if (++it != tokens.end())
        sscanf((*it).c_str(), "%hd", &sz);
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
          if (r)
            PRINT1("[ matched ] elap: %f sec\n", d);
          else
            PRINT1("[not found] elap: %f sec\n", d);
        }
        else
          PERROR("Invalid entry\n");
      }
    }
    else if (token == "INSERT")
    {
      if (++it != tokens.end() && g_db)
      {
        std::string param(*it);
        cidr_address cidr;
        if (create_cidr_address(&cidr, param.c_str()) == 0)
        {
          double t0 = timestamp();
          int r = create_record(g_db, &cidr);
          double d = timestamp() - t0;
          if (r == 0)
            PRINT("Entry already exists\n");
          else if (r == 1)
            PRINT1("Inserted, elap: %f sec\n", d);
          else
            PERROR1("Internal error (%d)\n", r);
        }
        else
          PERROR("Invalid argument\n");
      }
    }
    else if (token == "LOAD")
    {
      if (++it != tokens.end() && g_db)
      {
        std::string param(*it);
        double t0 = timestamp();
        int r = fill_database_from_text(g_db, param.c_str());
        double d = timestamp() - t0;
        if (r == 0)
          PRINT1("Loaded, elap: %f sec\n", d);
        else
          PERROR1("Error (%d)\n", r);
      }
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
          PERROR1("Error (%d)\n", LASTERROR);
      }
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
