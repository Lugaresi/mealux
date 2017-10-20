# mealux
Collection of CRUX ports, mainly for my own.

## Quickstart ##

Download mealux.git:

```
curl -o /etc/ports/mealux.git https://raw.githubusercontent.com/Lugaresi/mealux/master/mealux.git
```

Enable the 'contrib' ports collection as [described in the CRUX handbook](https://crux.nu/Main/Handbook3-3#ntoc42)

Add 'prtdir /usr/ports/mealux' to **/etc/prt-get.conf**, preferably before 'contrib', 'core', 'opt', and 'xorg'.

Update ports collections:

```
ports -u
```

Enjoy and submit bugs / updates, they will be largely ignored until I look into github!
