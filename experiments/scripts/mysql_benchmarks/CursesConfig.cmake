# set(CURSES_FOUND TRUE)
# set(CURSES_INCLUDE_DIR "/tmp/IPRA-exp/build/benchmarks/mysql/ncurses-6.3/install/include")
# set(CURSES_INCLUDE_PATH "/tmp/IPRA-exp/build/benchmarks/mysql/ncurses-6.3/install/include")
# set(CURSES_LIBRARY ncurses)
# set(CURSES_FORM_LIBRARY form)

FIND_LIBRARY(CURSES_LIBRARY ncurses form
    PATHS /tmp/IPRA-exp/build/benchmarks/mysql/ncurses-6.3/install/lib
    NO_DEFAULT_PATH
)
SET(CURSES_LIBRARIES ${CURSES_LIBRARY})
FIND_PATH(CURSES_INCLUDE_DIR ncurses/curses.h ncurses/ncurses.h
    PATHS /tmp/IPRA-exp/build/benchmarks/mysql/ncurses-6.3/install/include
    NO_DEFAULT_PATH
)

set(CURSES_CURSES_H_PATH "${CURSES_INCLUDE_PATH}/ncurses/curses.h")
set(CURSES_NCURSES_H_PATH "${CURSES_INCLUDE_PATH}/ncurses/ncurses.h")
set(CURSES_HAVE_CURSES_H "${CURSES_INCLUDE_PATH}/ncurses/curses.h")
set(CURSES_HAVE_NCURSES_H "${CURSES_INCLUDE_PATH}/ncurses/ncurses.h")