

#define mrp_c

#include "mr.h"

#include "mr_auxlib.h"
#include "mr_lib.h"


/*
** generic extra include file
*/
#ifdef MRP_USERCONFIG
#include MRP_USERCONFIG
#endif


/*
** definition of `isatty'
*/
#ifdef _POSIX_C_SOURCE
#define stdin_is_tty()	isatty(0)
#else
#define stdin_is_tty()	1  /* assume stdin is a tty */
#endif



#ifndef PROMPT
#define PROMPT		"> "
#endif


#ifndef PROMPT2
#define PROMPT2		">> "
#endif

#ifndef PROGNAME
#define PROGNAME	"mr"
#endif

#ifndef mrp_userinit
#define mrp_userinit(L)		openstdlibs(L)
#endif


#ifndef MRP_EXTRALIBS
#define MRP_EXTRALIBS	/* empty */
#endif


static mrp_State *L = NULL;

static const char *progname = PROGNAME;



static const mr_L_reg mrplibs[] = {
  {"base", mrp_open_base},
  {"table", mrp_open_table},
  {"file", mrp_open_file},
  {"string", mrp_open_string},
  {"math", mrp_open_math},
  {"debug", mrp_open_debug},
  {"loadlib", mrp_open_loadlib},
  /* add your libraries here */
  MRP_EXTRALIBS
  {NULL, NULL}
};



static void lstop (mrp_State *l, mrp_Debug *ar) {
  (void)ar;  /* unused arg. */
  mrp_sethook(l, NULL, 0, 0);
  mr_L_error(l, "interrupted!");
  
}


static void laction (int i) {
  signal(i, SIG_DFL); /* if another SIGINT happens before lstop,
                              terminate process (default action) */
  mrp_sethook(L, lstop, MRP_MASKCALL | MRP_MASKRET | MRP_MASKCOUNT, 1);
}


static void print_usage (void) {
  fprintf(stderr,
  "usage: %s [options] [script [args]].\n"
  "Available options are:\n"
  "  -        execute stdin as a file\n"
  "  -e stat  execute string `stat'\n"
  "  -i       enter interactive mode after executing `script'\n"
  "  -l name  load and run library `name'\n"
  "  -v       show version information\n"
  "  --       stop handling options\n" ,
  progname);
}


static void l_message (const char *pname, const char *msg) {
  if (pname) fprintf(stderr, "%s: ", pname);
  fprintf(stderr, "%s\n", msg);
}


static int report (int status) {
  const char *msg;
  if (status) {
    msg = mrp_tostring(L, -1);
    if (msg == NULL) msg = "(error with no message)";
    l_message(progname, msg);
    mrp_pop(L, 1);
  }
  return status;
}


static int lcall (int narg, int clear) {
  int status;
  int base = mrp_gettop(L) - narg;  /* function index */
  mrp_pushliteral(L, "_TRACEBACK");
  mrp_rawget(L, MRP_GLOBALSINDEX);  /* get traceback function */
  mrp_insert(L, base);  /* put it under chunk and args */
  signal(SIGINT, laction);
  status = mrp_pcall(L, narg, (clear ? 0 : MRP_MULTRET), base);
  signal(SIGINT, SIG_DFL);
  mrp_remove(L, base);  /* remove traceback function */
  return status;
}


static void print_version (void) {
  l_message(NULL, MR_VERSION "  " MR_COPYRIGHT);
}


static void getargs (char *argv[], int n) {
  int i;
  mrp_newtable(L);
  for (i=0; argv[i]; i++) {
    mrp_pushnumber(L, i - n);
    mrp_pushstring(L, argv[i]);
    mrp_rawset(L, -3);
  }
  /* arg.n = maximum index in table `arg' */
  mrp_pushliteral(L, "n");
  mrp_pushnumber(L, i-n-1);
  mrp_rawset(L, -3);
}


static int docall (int status) {
  if (status == 0) status = lcall(0, 1);
  return report(status);
}


static int file_input (const char *name) {
  return docall(mr_L_loadfile(L, name));
}


static int dostring (const char *s, const char *name) {
  return docall(mr_L_loadbuffer(L, s, STRLEN(s), name));
}


static int load_file (const char *name) {
  mrp_pushliteral(L, "require");
  mrp_rawget(L, MRP_GLOBALSINDEX);
  if (!mrp_isfunction(L, -1)) {  /* no `require' defined? */
    mrp_pop(L, 1);
    return file_input(name);
  }
  else {
    mrp_pushstring(L, name);
    return report(lcall(1, 1));
  }
}


/*
** this macro can be used by some `history' system to save lines
** read in manual input
*/
#ifndef mrp_saveline
#define mrp_saveline(L,line)	/* empty */
#endif


/*
** this macro defines a function to show the prompt and reads the
** next line for manual input
*/
#ifndef mrp_readline
#define mrp_readline(L,prompt)		readline(L,prompt)

/* maximum length of an input line */
#ifndef MAXINPUT
#define MAXINPUT	512
#endif


static int readline (mrp_State *l, const char *prompt) {
  static char buffer[MAXINPUT];
  if (prompt) {
    fputs(prompt, stdout);
    fflush(stdout);
  }
  if (fgets(buffer, sizeof(buffer), stdin) == NULL)
    return 0;  /* read fails */
  else {
    mrp_pushstring(l, buffer);
    return 1;
  }
}

#endif


static const char *get_prompt (int firstline) {
  const char *p = NULL;
  mrp_pushstring(L, firstline ? "_PROMPT" : "_PROMPT2");
  mrp_rawget(L, MRP_GLOBALSINDEX);
  p = mrp_tostring(L, -1);
  if (p == NULL) p = (firstline ? PROMPT : PROMPT2);
  mrp_pop(L, 1);  /* remove global */
  return p;
}


static int incomplete (int status) {
  if (status == MRP_ERRSYNTAX &&
         strstr(mrp_tostring(L, -1), "near `<eof>'") != NULL) {
    mrp_pop(L, 1);
    return 1;
  }
  else
    return 0;
}


static int load_string (void) {
  int status;
  mrp_settop(L, 0);
  if (mrp_readline(L, get_prompt(1)) == 0)  /* no input? */
    return -1;
  if (mrp_tostring(L, -1)[0] == '=') {  /* line starts with `=' ? */
    mrp_pushfstring(L, "return %s", mrp_tostring(L, -1)+1);/* `=' -> `return' */
    mrp_remove(L, -2);  /* remove original line */
  }
  for (;;) {  /* repeat until gets a complete line */
    status = mr_L_loadbuffer(L, mrp_tostring(L, 1), mrp_strlen(L, 1), "=stdin");
    if (!incomplete(status)) break;  /* cannot try to add lines? */
    if (mrp_readline(L, get_prompt(0)) == 0)  /* no more input? */
      return -1;
    mrp_concat(L, mrp_gettop(L));  /* join lines */
  }
  mrp_saveline(L, mrp_tostring(L, 1));
  mrp_remove(L, 1);  /* remove line */
  return status;
}


static void manual_input (void) {
  int status;
  const char *oldprogname = progname;
  progname = NULL;
  while ((status = load_string()) != -1) {
    if (status == 0) status = lcall(0, 0);
    report(status);
    if (status == 0 && mrp_gettop(L) > 0) {  /* any result to print? */
      mrp_getglobal(L, "print");
      mrp_insert(L, 1);
      if (mrp_pcall(L, mrp_gettop(L)-1, 0, 0) != 0)
        l_message(progname, mrp_pushfstring(L, "error calling `print' (%s)",
                                               mrp_tostring(L, -1)));
    }
  }
  mrp_settop(L, 0);  /* clear stack */
  fputs("\n", stdout);
  progname = oldprogname;
}


static int handle_argv (char *argv[], int *interactive) {
  if (argv[1] == NULL) {  /* no more arguments? */
    if (stdin_is_tty()) {
      print_version();
      manual_input();
    }
    else
      file_input(NULL);  /* executes stdin as a file */
  }
  else {  /* other arguments; loop over them */
    int i;
    for (i = 1; argv[i] != NULL; i++) {
      if (argv[i][0] != '-') break;  /* not an option? */
      switch (argv[i][1]) {  /* option */
        case '-': {  /* `--' */
          if (argv[i][2] != '\0') {
            print_usage();
            return 1;
          }
          i++;  /* skip this argument */
          goto endloop;  /* stop handling arguments */
        }
        case '\0': {
          file_input(NULL);  /* executes stdin as a file */
          break;
        }
        case 'i': {
          *interactive = 1;
          break;
        }
        case 'v': {
          print_version();
          break;
        }
        case 'e': {
          const char *chunk = argv[i] + 2;
          if (*chunk == '\0') chunk = argv[++i];
          if (chunk == NULL) {
            print_usage();
            return 1;
          }
          if (dostring(chunk, "=<command line>") != 0)
            return 1;
          break;
        }
        case 'l': {
          const char *filename = argv[i] + 2;
          if (*filename == '\0') filename = argv[++i];
          if (filename == NULL) {
            print_usage();
            return 1;
          }
          if (load_file(filename))
            return 1;  /* stop if file fails */
          break;
        }
        case 'c': {
          l_message(progname, "option `-c' is deprecated");
          break;
        }
        case 's': {
          l_message(progname, "option `-s' is deprecated");
          break;
        }
        default: {
          print_usage();
          return 1;
        }
      }
    } endloop:
    if (argv[i] != NULL) {
      const char *filename = argv[i];
      getargs(argv, i);  /* collect arguments */
      mrp_setglobal(L, "arg");
      return file_input(filename);  /* stop scanning arguments */
    }
  }
  return 0;
}


static void openstdlibs (mrp_State *l) {
  const mr_L_reg *lib = mrplibs;
  for (; lib->func; lib++) {
    lib->func(l);  /* open library */
    mrp_settop(l, 0);  /* discard any results */
  }
}


static int handle_mrpinit (void) {
  const char *init = getenv("MRP_INIT");
  if (init == NULL) return 0;  /* status OK */
  else if (init[0] == '@')
    return file_input(init+1);
  else
    return dostring(init, "=MRP_INIT");
}


struct Smain {
  int argc;
  char **argv;
  int status;
};


static int pmain (mrp_State *l) {
  struct Smain *s = (struct Smain *)mrp_touserdata(l, 1);
  int status;
  int interactive = 0;
  if (s->argv[0] && s->argv[0][0]) progname = s->argv[0];
  L = l;
  mrp_userinit(l);  /* open libraries */
  status = handle_mrpinit();
  if (status == 0) {
    status = handle_argv(s->argv, &interactive);
    if (status == 0 && interactive) manual_input();
  }
  s->status = status;
  return 0;
}


int main (int argc, char *argv[]) {
  int status;
  struct Smain s;
  mrp_State *l = mrp_open();  /* create state */
  if (l == NULL) {
    l_message(argv[0], "cannot create state: not enough memory");
    return EXIT_FAILURE;
  }
  s.argc = argc;
  s.argv = argv;
  status = mrp_cpcall(l, &pmain, &s);
  report(status);
  mrp_close(l);
  return (status || s.status) ? EXIT_FAILURE : EXIT_SUCCESS;
}

