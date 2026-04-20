FROM php:8.1-apache

WORKDIR /var/www/html

COPY . .

RUN a2enmod rewrite

EXPOSE 8080

CMD ["apache2-foreground"]
