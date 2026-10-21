FROM php:8.2-apache
RUN docker-php-ext-install mysqli

RUN apt-get update && apt-get install -y msmtp && rm -rf /var/lib/apt/lists/*

RUN echo "sendmail_path = /usr/bin/msmtp -t" > /usr/local/etc/php/conf.d/mail.ini

RUN echo "account default\nhost mailhog\nport 1025\nfrom noreply@ecommercelab.local\nauto_from off" > /etc/msmtprc \
    && chmod 644 /etc/msmtprc

COPY login.php /var/www/html/index.php
COPY totp.php /var/www/html/totp.php
COPY productos.php /var/www/html/productos.php
COPY usuarios.php /var/www/html/usuarios.php
COPY registro.php /var/www/html/registro.php
COPY verificar.php /var/www/html/verificar.php
COPY logout.php /var/www/html/logout.php
COPY session_helper.php /var/www/html/session_helper.php
COPY carrito.php /var/www/html/carrito.php
COPY style.css /var/www/html/style.css

