FROM httpd:2.4-alpine

# Copy configuration
COPY httpd.conf /usr/local/apache2/conf/httpd.conf
COPY .htaccess /usr/local/apache2/htdocs/.htaccess

# Create vulnerable directory structure
RUN mkdir -p /usr/local/apache2/htdocs/admin \
    /usr/local/apache2/htdocs/backup \
    /usr/local/apache2/htdocs/config \
    /usr/local/apache2/htdocs/cgi-bin

# Copy vulnerable content
COPY index.html /usr/local/apache2/htdocs/
COPY admin/ /usr/local/apache2/htdocs/admin/
COPY backup/ /usr/local/apache2/htdocs/backup/
COPY cgi-bin/ /usr/local/apache2/cgi-bin/

EXPOSE 80
