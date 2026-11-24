FROM php:8.2-apache
RUN docker-php-ext-install mysqli

RUN apt-get update && apt-get install -y msmtp && rm -rf /var/lib/apt/lists/*

RUN echo "sendmail_path = /usr/bin/msmtp -t" > /usr/local/etc/php/conf.d/mail.ini

RUN echo "account default\nhost mailhog\nport 1025\nfrom noreply@ecommercelab.local\nauto_from off" > /etc/msmtprc \
    && chmod 644 /etc/msmtprc

# Copiamos TODOS los archivos de la carpeta app a /var/www/html/
COPY . /var/www/html/