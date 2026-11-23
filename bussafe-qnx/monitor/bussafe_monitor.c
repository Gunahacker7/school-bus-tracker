/*
 * bussafe_monitor.c — BusSafe QNX safety-monitor service
 *
 * QNX 8.0 native service implementing the boarding-safety core of the
 * School Bus Tracker (QNX edition, "BusSafe QNX"):
 *
 *   - route session lifecycle (STARTROUTE / ENDROUTE)
 *   - per-student state tracking: EXPECTED -> ONBOARD -> ALIGHTED
 *   - alert generation at ENDROUTE:
 *       ALERT STILL_ONBOARD  <id>  student boarded but never alighted
 *       ALERT NEVER_BOARDED  <id>  expected student never boarded
 *
 * Interface: line-based TCP, port 4570 (BUSSAFE_PORT env override).
 * One command per line, LF or CRLF terminated. One reply block per command:
 * every reply ends with a line containing only "." so clients can frame
 * multi-line replies (STATUS, ENDROUTE) reliably.
 *
 * Persistence (v1.1): session state is saved to a state file on every
 * state-changing event and reloaded at startup, so a mid-route service
 * restart recovers the route, the roster and every student's state
 * exactly. Default path /data/var/bussafe/state (BUSSAFE_STATE env or
 * argv[2] override). Writes are atomic (temp file + rename); a missing
 * or corrupt state file never prevents startup — the service logs the
 * problem and starts fresh.
 *
 * Commands:
 *   PING                      -> OK PONG
 *   STARTROUTE <route_id>     -> OK ROUTE_STARTED <route_id>
 *   ADDSTUDENT <student_id>   -> OK EXPECTED <student_id>     (roster, pre-boarding)
 *   BOARD <student_id>        -> OK BOARDED <student_id>      (auto-registers if unknown)
 *   ALIGHT <student_id>       -> OK ALIGHTED <student_id>
 *   STATUS                    -> ROUTE/STUDENT/COUNT lines
 *   ENDROUTE                  -> OK ROUTE_ENDED <route_id> + ALERT lines (if any)
 *   QUIT                      -> OK BYE (closes this connection)
 *
 * Errors: ERR <CODE> <message>
 *
 * Single client at a time (sequential accept loop) — matches the dev
 * QEMU target; state persists across connections and across service
 * restarts (state file). Every event and alert is also written to
 * stdout (service log).
 *
 * Build (QNX SDP 8.0):
 *   qcc -V gcc_ntox86_64 -o bussafe_monitor bussafe_monitor.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_PORT   4570
#define MAX_STUDENTS   512
#define ID_LEN         48
#define LINE_LEN       256

typedef enum { ST_EXPECTED = 0, ST_ONBOARD = 1, ST_ALIGHTED = 2 } student_state_t;

typedef struct {
    char id[ID_LEN];
    student_state_t state;
    time_t board_time;
    time_t alight_time;
} student_t;

static student_t g_students[MAX_STUDENTS];
static int       g_nstudents = 0;
static int       g_route_active = 0;
static char      g_route_id[ID_LEN] = "";
static int       g_alert_count = 0;   /* alerts raised this route */

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* ---- Persistence ---------------------------------------------------- */
#define STATE_MAGIC "BUSSAFE_STATE 1"
static char g_state_path[256] = "/data/var/bussafe/state";

static void ensure_state_dirs(void)
{
    /* mkdir each prefix of the state file's directory part (EEXIST ok). */
    char tmp[256];
    size_t i, len = strlen(g_state_path);
    if (len >= sizeof(tmp)) return;
    strcpy(tmp, g_state_path);
    for (i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            mkdir(tmp, 0755);
            tmp[i] = '/';
        }
    }
}

static const char *state_name(student_state_t s)
{
    switch (s) {
        case ST_ONBOARD:  return "ONBOARD";
        case ST_ALIGHTED: return "ALIGHTED";
        default:          return "EXPECTED";
    }
}

static student_t *find_student(const char *id)
{
    int i;
    for (i = 0; i < g_nstudents; i++)
        if (strcmp(g_students[i].id, id) == 0) return &g_students[i];
    return NULL;
}

static student_t *add_student(const char *id)
{
    student_t *s;
    if (g_nstudents >= MAX_STUDENTS) return NULL;
    s = &g_students[g_nstudents++];
    memset(s, 0, sizeof(*s));
    strncpy(s->id, id, ID_LEN - 1);
    s->state = ST_EXPECTED;
    return s;
}

static void log_event(const char *fmt, const char *a, const char *b)
{
    char ts[32];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmv);
    if (b)      printf("[%s] %s %s %s\n", ts, fmt, a, b);
    else if (a) printf("[%s] %s %s\n", ts, fmt, a);
    else        printf("[%s] %s\n", ts, fmt);
    fflush(stdout);
}

/* Save the full session state atomically (temp file + rename), so a
 * crash mid-write can never leave a torn state file behind. A failed
 * save is logged but never breaks the command path. */
static void save_state(void)
{
    char tmp_path[300];
    FILE *f;
    int i;
    ensure_state_dirs();
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", g_state_path);
    f = fopen(tmp_path, "w");
    if (!f) {
        log_event("STATE_SAVE_FAILED", g_state_path, NULL);
        return;
    }
    fprintf(f, "%s\n", STATE_MAGIC);
    fprintf(f, "ROUTE_ACTIVE %d\n", g_route_active);
    fprintf(f, "ROUTE_ID %s\n", g_route_active ? g_route_id : "-");
    fprintf(f, "ALERTS %d\n", g_alert_count);
    for (i = 0; i < g_nstudents; i++) {
        fprintf(f, "STUDENT %s %d %lld %lld\n", g_students[i].id,
                (int)g_students[i].state,
                (long long)g_students[i].board_time,
                (long long)g_students[i].alight_time);
    }
    fprintf(f, "END\n");
    if (fclose(f) != 0 || rename(tmp_path, g_state_path) != 0)
        log_event("STATE_SAVE_FAILED", g_state_path, NULL);
}

/* Load state saved by a previous run. Missing file = fresh start;
 * corrupt file = log and start fresh (never crash on bad state). */
static void load_state(void)
{
    FILE *f = fopen(g_state_path, "r");
    char line[256];
    if (!f) {
        log_event("STATE_LOAD_NONE", g_state_path, NULL);
        return;
    }
    if (!fgets(line, sizeof(line), f) ||
        strncmp(line, STATE_MAGIC, strlen(STATE_MAGIC)) != 0) {
        fclose(f);
        log_event("STATE_LOAD_BAD_HEADER", g_state_path, NULL);
        return;
    }
    g_nstudents = 0;
    g_route_active = 0;
    g_route_id[0] = '\0';
    g_alert_count = 0;
    while (fgets(line, sizeof(line), f)) {
        char id[ID_LEN];
        int st;
        long long bt, at;
        student_t *s;
        if (sscanf(line, "ROUTE_ACTIVE %d", &g_route_active) == 1) continue;
        if (sscanf(line, "ROUTE_ID %47s", id) == 1) {
            if (strcmp(id, "-") != 0)
                strncpy(g_route_id, id, ID_LEN - 1);
            continue;
        }
        if (sscanf(line, "ALERTS %d", &g_alert_count) == 1) continue;
        if (strncmp(line, "END", 3) == 0) break;
        if (sscanf(line, "STUDENT %47s %d %lld %lld", id, &st, &bt, &at) == 4) {
            if (st < 0 || st > 2) continue;
            s = add_student(id);
            if (!s) break;
            s->state = (student_state_t)st;
            s->board_time = (time_t)bt;
            s->alight_time = (time_t)at;
        }
        /* unknown lines are ignored (forward-compatible) */
    }
    fclose(f);
    if (!g_route_active) g_route_id[0] = '\0';
    g_route_id[ID_LEN - 1] = '\0';
    log_event("STATE_LOADED", g_state_path, NULL);
    printf("restored: route=%s active=%d students=%d alerts=%d\n",
           g_route_active ? g_route_id : "NONE", g_route_active,
           g_nstudents, g_alert_count);
    fflush(stdout);
}

/* Send a reply block: lines..., then "." terminator. */
static void reply_begin(int fd) { (void)fd; }
static void reply_line(int fd, const char *line)
{
    char buf[LINE_LEN + 2];
    snprintf(buf, sizeof(buf), "%s\n", line);
    send(fd, buf, strlen(buf), 0);
}
static void reply_end(int fd) { send(fd, ".\n", 2, 0); }
static void reply1(int fd, const char *line) { reply_line(fd, line); reply_end(fd); }

static void handle_command(int fd, char *line)
{
    char cmd[32] = "", arg[ID_LEN] = "";
    char out[LINE_LEN];
    int n = sscanf(line, "%31s %47s", cmd, arg);
    if (n <= 0) { reply1(fd, "ERR EMPTY empty command"); return; }

    if (strcasecmp(cmd, "PING") == 0) {
        reply1(fd, "OK PONG");
    }
    else if (strcasecmp(cmd, "STARTROUTE") == 0) {
        if (n < 2) { reply1(fd, "ERR BADARG STARTROUTE needs a route id"); return; }
        if (g_route_active) { reply1(fd, "ERR ROUTE_ACTIVE a route is already active; ENDROUTE first"); return; }
        /* New route: clear previous session state. */
        g_nstudents = 0;
        g_alert_count = 0;
        strncpy(g_route_id, arg, ID_LEN - 1);
        g_route_id[ID_LEN - 1] = '\0';
        g_route_active = 1;
        save_state();
        log_event("ROUTE_START", g_route_id, NULL);
        snprintf(out, sizeof(out), "OK ROUTE_STARTED %s", g_route_id);
        reply1(fd, out);
    }
    else if (strcasecmp(cmd, "ADDSTUDENT") == 0) {
        student_t *s;
        if (n < 2) { reply1(fd, "ERR BADARG ADDSTUDENT needs a student id"); return; }
        if (!g_route_active) { reply1(fd, "ERR NO_ROUTE no active route; STARTROUTE first"); return; }
        s = find_student(arg);
        if (!s) {
            s = add_student(arg);
            if (s) save_state();
        }
        if (!s) { reply1(fd, "ERR FULL student table full"); return; }
        log_event("EXPECTED", s->id, NULL);
        snprintf(out, sizeof(out), "OK EXPECTED %s", s->id);
        reply1(fd, out);
    }
    else if (strcasecmp(cmd, "BOARD") == 0) {
        student_t *s;
        if (n < 2) { reply1(fd, "ERR BADARG BOARD needs a student id"); return; }
        if (!g_route_active) { reply1(fd, "ERR NO_ROUTE no active route; STARTROUTE first"); return; }
        s = find_student(arg);
        if (!s) s = add_student(arg);   /* walk-on: auto-register */
        if (!s) { reply1(fd, "ERR FULL student table full"); return; }
        if (s->state == ST_ONBOARD) {
            snprintf(out, sizeof(out), "ERR ALREADY_ONBOARD %s", s->id);
            reply1(fd, out);
            return;
        }
        s->state = ST_ONBOARD;
        s->board_time = time(NULL);
        save_state();
        log_event("BOARDED", s->id, NULL);
        snprintf(out, sizeof(out), "OK BOARDED %s", s->id);
        reply1(fd, out);
    }
    else if (strcasecmp(cmd, "ALIGHT") == 0) {
        student_t *s;
        if (n < 2) { reply1(fd, "ERR BADARG ALIGHT needs a student id"); return; }
        if (!g_route_active) { reply1(fd, "ERR NO_ROUTE no active route; STARTROUTE first"); return; }
        s = find_student(arg);
        if (!s) {
            snprintf(out, sizeof(out), "ERR UNKNOWN_STUDENT %s", arg);
            reply1(fd, out);
            return;
        }
        if (s->state != ST_ONBOARD) {
            snprintf(out, sizeof(out), "ERR NOT_ONBOARD %s", s->id);
            reply1(fd, out);
            return;
        }
        s->state = ST_ALIGHTED;
        s->alight_time = time(NULL);
        save_state();
        log_event("ALIGHTED", s->id, NULL);
        snprintf(out, sizeof(out), "OK ALIGHTED %s", s->id);
        reply1(fd, out);
    }
    else if (strcasecmp(cmd, "STATUS") == 0) {
        int i, n_on = 0, n_al = 0, n_ex = 0;
        for (i = 0; i < g_nstudents; i++) {
            if (g_students[i].state == ST_ONBOARD) n_on++;
            else if (g_students[i].state == ST_ALIGHTED) n_al++;
            else n_ex++;
        }
        reply_begin(fd);
        if (g_route_active) {
            snprintf(out, sizeof(out), "ROUTE %s ACTIVE", g_route_id);
        } else {
            snprintf(out, sizeof(out), "ROUTE NONE INACTIVE");
        }
        reply_line(fd, out);
        snprintf(out, sizeof(out), "COUNT TOTAL %d ONBOARD %d ALIGHTED %d EXPECTED %d",
                 g_nstudents, n_on, n_al, n_ex);
        reply_line(fd, out);
        for (i = 0; i < g_nstudents; i++) {
            snprintf(out, sizeof(out), "STUDENT %s %s",
                     g_students[i].id, state_name(g_students[i].state));
            reply_line(fd, out);
        }
        reply_end(fd);
    }
    else if (strcasecmp(cmd, "ENDROUTE") == 0) {
        int i;
        if (!g_route_active) { reply1(fd, "ERR NO_ROUTE no active route"); return; }
        reply_begin(fd);
        snprintf(out, sizeof(out), "OK ROUTE_ENDED %s", g_route_id);
        reply_line(fd, out);
        /* Safety sweep: the core check of the whole system. */
        for (i = 0; i < g_nstudents; i++) {
            if (g_students[i].state == ST_ONBOARD) {
                snprintf(out, sizeof(out), "ALERT STILL_ONBOARD %s", g_students[i].id);
                reply_line(fd, out);
                log_event("ALERT STILL_ONBOARD", g_students[i].id, g_route_id);
                g_alert_count++;
            } else if (g_students[i].state == ST_EXPECTED) {
                snprintf(out, sizeof(out), "ALERT NEVER_BOARDED %s", g_students[i].id);
                reply_line(fd, out);
                log_event("ALERT NEVER_BOARDED", g_students[i].id, g_route_id);
                g_alert_count++;
            }
        }
        snprintf(out, sizeof(out), "ALERTS %d", g_alert_count);
        reply_line(fd, out);
        reply_end(fd);
        log_event("ROUTE_END", g_route_id, NULL);
        g_route_active = 0;
        g_route_id[0] = '\0';
        save_state();
    }
    else if (strcasecmp(cmd, "QUIT") == 0) {
        reply1(fd, "OK BYE");
        /* handled by caller: close connection */
        shutdown(fd, SHUT_RD);
    }
    else {
        snprintf(out, sizeof(out), "ERR UNKNOWN_COMMAND %s", cmd);
        reply1(fd, out);
    }
}

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT;
    const char *env_port = getenv("BUSSAFE_PORT");
    const char *env_state = getenv("BUSSAFE_STATE");
    int listen_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;

    if (env_port && atoi(env_port) > 0) port = atoi(env_port);
    if (argc > 1 && atoi(argv[1]) > 0) port = atoi(argv[1]);
    if (env_state && env_state[0]) {
        strncpy(g_state_path, env_state, sizeof(g_state_path) - 1);
        g_state_path[sizeof(g_state_path) - 1] = '\0';
    }
    if (argc > 2 && argv[2][0]) {
        strncpy(g_state_path, argv[2], sizeof(g_state_path) - 1);
        g_state_path[sizeof(g_state_path) - 1] = '\0';
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((unsigned short)port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(listen_fd, 4) < 0) { perror("listen"); return 1; }

    load_state();
    log_event("BUSSAFE_MONITOR_START", NULL, NULL);
    printf("bussafe_monitor listening on port %d (state file: %s)\n",
           port, g_state_path);
    fflush(stdout);

    while (!g_stop) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        char line[LINE_LEN];
        int pos = 0;

        client_fd = accept(listen_fd, (struct sockaddr *)&caddr, &clen);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        log_event("CLIENT_CONNECT", inet_ntoa(caddr.sin_addr), NULL);
        reply1(client_fd, "BUSSAFE 1.1 READY");

        /* Read byte-wise into lines; simple and robust for this protocol. */
        for (;;) {
            char ch;
            ssize_t r = recv(client_fd, &ch, 1, 0);
            if (r <= 0) break;
            if (ch == '\n') {
                line[pos] = '\0';
                if (pos > 0 && line[pos - 1] == '\r') line[pos - 1] = '\0';
                /* Empty lines get a clean ERR EMPTY reply (never silence,
                 * never a crash); overlong lines are truncated at
                 * LINE_LEN and parsed as their first token(s). */
                handle_command(client_fd, line);
                pos = 0;
            } else if (pos < LINE_LEN - 1) {
                line[pos++] = ch;
            }
        }
        close(client_fd);
        log_event("CLIENT_DISCONNECT", NULL, NULL);
    }

    close(listen_fd);
    log_event("BUSSAFE_MONITOR_STOP", NULL, NULL);
    return 0;
}
