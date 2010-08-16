vpnoo
=====

vpnoo is a very simple IPsec/XAuth client for Mac OS X. It uses racoon
as backend. It is targeted at providing a simple IPsec client for
enterprise users. It is not a general IPsec client like IPSecuritas_.

.. _IPSecuritas: http://www.lobotomo.com/products/IPSecuritas/

Features
--------

What vpnoo does:
 - It provides a simple dialog with login, password and a connect button.
 - It supports either certificates or PSK but there is now easy way
   for the user to configure them (see `Installation`_).
 - It will try to diagnose any problems that may arise.

What vpnoo does not:
 - It does not ask for certificate or PSK, just login/password (see
   `Installation`_ and `Certificate installation`_).
 - It does not do plain IPsec, nor L2TP over IPsec.
 - It does not allow to setup several tunnels at once, it even
   conflicts with built-in tunnels because it kills system racoon.
 - It only works with split networks (but this can easily be worked
   around if you tweak some script).

Installation
------------

This is the hard part. There is no precompiled version of vpnoo. You
need to checkout sources from a git repository:

 $ git checkout git://git.luffy.cx/vpnoo.git

Alternatively, you can grab a tarball from http://cgit.luffy.cx/vpnoo/

Open the project in XCode. Here, you need to customize ``vpn.plist``
which contains the list of allowed VPN end-points. The name can be
anything since it is only used to display to the user.

Then, you may need to customize ``racoon.conf`` which is a
template. Read the comments at the beginning. However, the default
configuration should be fine.

You may have to customize ``phase1`` script as well, for example if
you don't use split network or if you want to configure DNS
differently (racoon does not support split DNS as a client, you can
work around this limitation in the script). No special indications
here, you are on your own.

If you are using PSK, you will need to add the file containing the PSK
as a resource. If you use certificate, you need to put the
certificates in the resources. If you don't want to use the same PSK
or certificate for every user, you will need to use some script to put
the PSK and the certificate in the right place and build a password
protected DMG image. Something like that :

 #!/bin/sh
 cp $USER.pem $USER.key cacertificate.pem "$ROOT/vpnoo.app/Contents/Resources/."
 hdiutil create -srcfolder "$ROOT" \
                -volname "$USERNAME's vpnoo" \
                -encryption AES-256 -stdinpass $USER.dmg < $PASSFILE

You can customize ``$ROOT`` folder with a background or additional
files for examples (symlinks to the certificates?).

The user will download its own DMG image from some semi-secure
repository (it is password protected but if somebody is able to
replace the image by its own, this is pretty bad), double click on
vpnoo icon, enter login and password and will be connected.

Certificate installation
------------------------

We said earlier that it is not possible for the user to install its
own certificate. This is not true. There is a hidden trick that will
allow a user to update its certificate: the user needs to drag and
drop its certificate on vpnoo window. The certificate must be in
PKCS#12 format. The certificate may be password protected. The
certificate must contain a user certificate, a user private key for
this certificate and a CA certificate. It will be installed as
``user.pem``, ``user.key`` and ``cacert.pem``.

Compatibility
-------------

Because racoon shipped in Mac OS X 10.5 (Leopard) does not support
XAuth, vpnoo requires Mac OS X 10.6 to work. Support of Mac OS X 10.5
may be added later.

Security
--------

vpnoo uses the keychain to store the password. On first use, it will
ask administrator privileges to install and enable an helper tool that
will be used to perform some operations like starting/stopping racoon
and starting racoonctl.

However, the current security of vpnoo is pretty bad. Once the
administrator has acknowledged the installation of the helper, a user
can gain administrator privileges pretty easily:
 - he can modify the template to execute another script than the one
   provided for phase 1 ; this script is executed by racoon with full
   admin rights
 - he can modify the script itself

Keep this in mind. There is no easy workaround. Even if the
administrator moves the whole application into the Application folder,
the problem still exists. The user cannot modify the template or the
script but he can modify the final configuration file in his
home. However, this is more difficult for a casual user.

Licensing
---------

vpnoo is distributed under the following license:
 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.

 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

