# Prefix?!
ac_add_options --prefix=/usr

# Specify the cross compile
#ac_add_options --target=x86_64-pc-mingw32
#ac_add_options --host=x86_64-pc-mingw32

# Build parameters
mk_add_options MOZ_OBJDIR=@TOPSRCDIR@/objdir-sm-release
ac_add_options --disable-debug
mk_add_options MOZ_MAKE_FLAGS="-j4"
ac_add_options --enable-strip

# Enabled Components
ac_add_options --enable-application=suite
ac_add_options --enable-default-toolkit=cairo-gtk2
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
#ac_add_options --enable-official-branding
ac_add_options --with-branding=suite/branding/Netscape

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
#ac_add_options --with-system-libevent
ac_add_options --enable-startup-notification
