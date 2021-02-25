# Script to search for jailbreak traces in iOS devices
# It does string searches of known jailbreak related apps kw in known log files

# Input
SOURCE_DIR="/morgue/102121-cubero/102121-01-1"
JAILBREAK_DIR="${SOURCE_DIR}/output/ios/jailbreak"
PLUGINS_DIR="/usr/local/rvt2/plugins/ios"

while getopts ":s:j:p:" opt; do
  case ${opt} in
    s ) SOURCE_DIR=$OPTARG
      ;;
    j ) JAILBREAK_DIR=$OPTARG
      ;;
    p ) PLUGINS_DIR=$OPTARG
      ;;
    : )
      echo "Invalid option: $OPTARG requires an argument" 1>&2
      exit
      ;;
    \? ) echo "Usage: cmd [-s] source_dir [-j] jailbreak_dir [-p] [plugin_dir]"
      exit
      ;;
  esac
done

# Files used
ALLOC_FILES="${SOURCE_DIR}/output/auxdir/alloc_files.txt"
JAILBREAK_FILES="${PLUGINS_DIR}/jailbreak_files"
JAILBREAK_APPS="${PLUGINS_DIR}/jailbreak_apps"
ALLOC_LOCATED="${SOURCE_DIR}/output/ios/jailbreak/alloc_jailbreak_files"
STRINGS_ALL="${SOURCE_DIR}/output/ios/jailbreak/strings_jailbreak_files"
SEARCH_RESULT="${SOURCE_DIR}/output/ios/jailbreak/jailbreak_result.txt"

locate_files() {
    while read file_regex; do
        #echo \'"${file_regex}"\'
        rg -N "${file_regex}" $ALLOC_FILES
    done < "${JAILBREAK_FILES}"
}

make_strings() {
    while read file; do
        #echo \'"${file}"\'
        srch_strings -f -a -t d "${SOURCE_DIR}/../${file}"
    done < "${ALLOC_LOCATED}"
}

search_jail_apps() {
    while read app; do
        #echo \'"${app}"\'
        rg -i -N "${app}" "${STRINGS_ALL}"
    done < "${JAILBREAK_APPS}"
}

# Main
if [ ! -e "${JAILBREAK_DIR}" ]; then
  mkdir "${JAILBREAK_DIR}"
fi
locate_files > $ALLOC_LOCATED
if [ ! -e "${STRINGS_ALL}" ]; then
  make_strings >> "${STRINGS_ALL}"
fi
search_jail_apps > "${SEARCH_RESULT}"
