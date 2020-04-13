#!/bin/sh
#
# lame script to install nullscan

BLUE='\033[1;34;10m'
RED='\033[1;31;10m'
YELLOW='\033[1;33;10m'
GREEN='\033[1;32;10m'
NORM='\033[0m'

SUCCESS=0
FAILURE=1

SHARE_PATH='/usr/share/nullscan'
CONF_PATH='/etc'
DOC_PATH='/usr/share/doc/nullscan'
LICENSE_PATH='/usr/share/licenses/nullscan'
MAN_PATH='/usr/share/man/man1'


msg()
{
  eopt='-e'

  # distros default shell without -e flag for echo
  $(egrep 'debian|ubuntu|kali' /proc/version > /dev/null 2>&1)
  other_distros=$?

  if [ $other_distros -eq $SUCCESS ]
  then
    eopt=''
  else
    eopt='-e'
  fi

  if [ "$1" = 'job' ]
  then
    echo $eopt "${BLUE}[+]${NORM} ${2}"
  elif [ "$1" = 'good' ]
  then
    echo $eopt "${GREEN}[*]${NORM} ${2}"
  elif [ "$1" = 'warn' ]
  then
    echo $eopt "${YELLOW}[!]${NORM} ${2}"
  elif [ "$1" = 'err' ]
  then
    echo $eopt "${RED}[-]${NORM} ${2}"
    exit $FAILURE
  else
    echo "${2}"
  fi

  return $SUCCESS
}


usage()
{
  msg "err" "usage: setup.sh install | uninstall"

  return $SUCCESS
}


create_dirs()
{
  mkdir -p $SHARE_PATH $DOC_PATH $LICENSE_PATH $MAN_PATH > /dev/null 2>&1 ||
    return $FAILURE

  return $SUCCESS
}

install_files()
{
  # source
  cp -a src "$SHARE_PATH/src" > /dev/null 2>&1 || return $FAILURE

  # config
  install -Dm 640 conf/nullscan.conf "$CONF_PATH/nullscan.conf" \
    > /dev/null 2>&1 || return $FAILURE

  # lists
  cp -a lists "$SHARE_PATH/lists" > /dev/null 2>&1 || return $FAILURE

  # docs - note: seems that dash shell cannot handle foo/{bar,baz} (!posix)
  install -Dm 644 -t "$DOC_PATH/" docs/AUTHORS docs/ChangeLog docs/DESCR \
    docs/*.txt docs/README docs/TESTED docs/THANKS docs/TODO > /dev/null 2>&1 ||
    return $FAILURE

  # man
  install -Dm 644 docs/nullscan.1 "$MAN_PATH/nullscan.1"

  # license
  install -Dm 644 docs/LICENSE "$LICENSE_PATH/LICENSE" > /dev/null 2>&1 ||
    return $FAILURE

  return $SUCCESS
}


create_symlink()
{
  ln -sf "$SHARE_PATH/src/nullscan.py" "$pkgdir/usr/bin/nullscan" ||
    return $FAILURE

  return $SUCCESS
}


uninstall()
{
  rm -rf $SHARE_PATH $DOC_PATH $LICENSE_PATH /etc/nullscan.conf \
    "$MAN_PATH/nullscan*" || return $FAILURE

  return $SUCCESS
}


main()
{
  if [ $# -ne 1 ]
  then
    usage
    exit $FAILURE
  fi

  if [ "$1" = "install" ]
  then
    msg 'job' 'w00t w00t, installing nullscan'

    msg 'job' 'creating necessary directories'
    create_dirs || msg 'err' 'could not create directories - are you r00t?'

    msg 'job' 'installing files'
    install_files || msg 'err' 'could not install files - are you r00t?'

    msg 'job' 'creating symlink to /usr/bin/nullscan'
    create_symlink || msg 'err' 'could not create symlink - are you r00t?'

    msg 'good' 'w00t w00t, install successfull'

    msg 'warn' "don't forget to install all py deps from docs/requirements.txt"
  elif [ "$1" = "uninstall" ]
  then
    msg 'job' 'uninstalling nullscan'
    uninstall || msg 'err' 'could not uninstall - do it yourself'
    msg 'good' 'uninstalled nullscan'
  else
    msg 'err' 'WHAT?'
  fi

  return $SUCCESS
}


main "${@}"

