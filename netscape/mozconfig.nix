# Prefix?!
ac_add_options --prefix=/usr

# Build parameters
mk_add_options MOZ_OBJDIR=@TOPSRCDIR@/objdir-sm-release
ac_add_options --disable-debug
ac_add_options --enable-optimize
mk_add_options MOZ_MAKE_FLAGS="-j4"
ac_add_options --enable-strip
ac_add_options --enable-rust

# Enabled Components
ac_add_options --enable-application=suite
ac_add_options --enable-calendar
ac_add_options --enable-default-toolkit=cairo-gtk3
ac_add_options --enable-extensions=default
#ac_add_options --enable-installer
ac_add_options --enable-jemalloc
#ac_add_options --enable-stdcxx-compat
ac_add_options --disable-gnomeui
ac_add_options --disable-necko-wifi
ac_add_options --disable-pulseaudio
ac_add_options --disable-gconf
ac_add_options --disable-dbus

# Other Features
ac_add_options --with-branding=suite/branding/Netscape

# Localization
ac_add_options --with-l10n-base=/usr/ports/mealux/netscape/work/src/seamonkey-2.49.5/locales
ac_add_options --enable-ui-locale=en-US
mk_add_options MOZ_CO_LOCALES=all

# Disabled (useless) stuff
ac_add_options --disable-updater
ac_add_options --disable-tests
ac_add_options --disable-accessibility
ac_add_options --disable-crashreporter


# Libraries I already have
ac_add_options --with-system-jpeg
ac_add_options --with-system-bz2
ac_add_options --with-system-zlib
ac_add_options --with-system-png
ac_add_options --with-system-nss
ac_add_options --with-system-nspr
ac_add_options --enable-system-cairo
ac_add_options --with-system-icu
ac_add_options --with-system-sqlite
ac_add_options --with-system-libvpx
ac_add_options --with-system-libevent
ac_add_options --enable-startup-notification

# All of this stolen from mozconfig.lto in mozilla source tree
# Use Clang as specified in manifest
export AR="llvm-ar"
export NM="llvm-nm"
export RANLIB="llvm-ranlib"

export CC="clang"
export CXX="clang++"


# Until Bug 1423822 is resolved
ac_add_options --disable-elf-hack

ac_add_options --enable-lto
