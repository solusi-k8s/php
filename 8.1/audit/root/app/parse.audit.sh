#!/bin/bash
filename=$1
sleep="10s"
total_line=500
if [ "$2" != "" ] ; then
  total_line=$2
fi
if [ "$3" != "" ] ; then
  sleep=$3
fi

if [ ! -f "$filename" ]; then
    echo "[$(date)] : file not exist ${filename}"
    exit 100
fi

# resolve links - $0 may be a softlink
PRG="$0"

while [ -h "$PRG" ]; do
  ls=`ls -ld "$PRG"`
  link=`expr "$ls" : '.*-> \(.*\)$'`
  if expr "$link" : '.*/.*' > /dev/null; then
    PRG="$link"
  else
    PRG=`dirname "$PRG"`/"$link"
  fi
done

# Get standard environment variables
PRGDIR=`dirname "$PRG"`

HOSTNAME=$(hostname)

if [ -f "${PRGDIR}/cfg.inc" ]; then
  echo "cfg"
  source ${PRGDIR}/cfg.inc
fi
echo $total_line


first=1;
line_before=0
while [ 1 ]; do
    tmpfile=$(mktemp)
    line_after=$(wc -l ${filename} | awk '{print $1}')
    line_compare=$(( line_after - line_before ))
    echo "[$(date)] : line_before=${line_before} line_after=${line_after} line_compare=${line_compare}"

    if [ "$first" = "1" ]; then
      echo "[$(date)] : start process apm log to tmpfile=${tmpfile} from original"
      echo -n "[$(date)] : "
      cp -vf ${filename} ${tmpfile}
    else
      if [ $line_compare -ge 0 ]; then
        line_tail=$((line_compare + ${total_line}))
        echo "[$(date)] : start process apm log to tmpfile=${tmpfile} with line_tail=${line_tail}"
        tail -n ${line_tail} ${filename} > ${tmpfile}
      else
        echo "[$(date)] : start process apm log to tmpfile=${tmpfile} with full"
        echo -n "[$(date)] : "
        cp -vf ${filename} ${tmpfile}
      fi
    fi
    first=0
    line_before=${line_after}

    ${PRGDIR}/parse.audit.php ${tmpfile} ${HOSTNAME}

    echo -n "[$(date)] : "
    rm -vf ${tmpfile}

    echo "[$(date)] : end process apm log to tmpfile=${tmpfile}"
    echo "[$(date)] : sleep ${sleep}"
    sleep ${sleep};
done
