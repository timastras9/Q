FROM php:7.4-apache

# Enable modules
RUN a2enmod rewrite
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Copy application
COPY . /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html
RUN chmod -R 755 /var/www/html

EXPOSE 80
