#!/bin/bash

LINKER=${LINKER:-ld}

# set -x

PATTERN='-o ([^ ].*) @(.*)$'
if [[ "$@" =~ ${PATTERN}  ]]; then
	DEP_FILE=`echo "$@" | sed -e 's/.*-o [^ ].* @\(.*\)/\1/'`
	DEPS=`cat ${DEP_FILE} | sed -e 's/\.o/\.bc/' | tr "\n" " "`
	TARGET_BC=`echo "$@" | sed -e 's/.*-o \([^ ]*\)\.o .*/\1\.bc/'`
	llvm-link -o ${TARGET_BC} ${DEPS} && llvm-dis ${TARGET_BC}
fi

# For 5.15
# PATTERN='-o ([^ ]*\.o)( .*\.(o|O))+'
# if [[ "$@" =~ ${PATTERN} ]]; then
#     TARGET_O="${BASH_REMATCH[1]}"
#     DEP_FILES="${BASH_REMATCH[2]}"
#     DEPS=$(echo "${DEP_FILES}" | sed -e 's/\.o/\.bc/g' | tr "\n" " ")
#     TARGET_BC=$(echo "${TARGET_O}" | sed -e 's/\.o$/.bc/')
#     llvm-link -o ${TARGET_BC} ${DEPS} && llvm-dis ${TARGET_BC}
# fi

${LINKER} "$@"
