package com.mycompany.server;


import java.io.*;
import static java.lang.System.out;
import java.net.*;
import java.nio.file.*;
import java.util.zip.*;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.*;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Server {
    private static String HOME_DIR;
    private static String DB_URL;
   
    /*static {
        try {
            HOME_DIR = new File("").getCanonicalPath().replace("\\", "/");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }*/
    private static final int PORT = 8000;

    public static void main(String[] args) {
        HOME_DIR = args[0];
        DB_URL = "jdbc:sqlite:" + args[1];
        try {
            Class.forName("org.sqlite.JDBC");
            System.out.println("SQLite JDBC Driver Registered!");

            try (Connection connection = DriverManager.getConnection(DB_URL)) {
                if (connection != null) {
                    System.out.println("Connected to the database!");
                } else {
                    System.out.println("Failed to connect to the database.");
                }
            } catch (SQLException e) {
                System.err.println("Connection to SQLite has failed.");
                e.printStackTrace();
            }
        } catch (ClassNotFoundException e) {
            System.err.println("SQLite JDBC Driver not found!");
            e.printStackTrace();
        }
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server started on port " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(new ClientHandler(clientSocket)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class ClientHandler implements Runnable {
        private final Socket clientSocket;

        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            OutputStream out = clientSocket.getOutputStream()) {

            String requestLine = in.readLine();
            if (requestLine == null || requestLine.isEmpty()) {
                sendErrorResponse(out, 400, "Bad Request");
                return;
            }
            System.out.println("Request Line: " + requestLine);

            String method = requestLine.split(" ")[0];
            String requestURI = requestLine.split(" ")[1];
            String[] parts = requestURI.split("\\?");
            String pathPart = parts[0];

            String cookieHeader = null;
            int contentLength = 0;
            String headerLine;
            while ((headerLine = in.readLine()) != null && !headerLine.isEmpty()) {
                if (headerLine.startsWith("Cookie:")) {
                    cookieHeader = headerLine.substring("Cookie:".length()).trim();
                } else if (headerLine.startsWith("Content-Length:")) {
                    contentLength = Integer.parseInt(headerLine.split(":")[1].trim());
                }
            }
            
            System.out.println("Cookie Header: " + cookieHeader);
            System.out.println("Content Length: " + contentLength);

            String sessionId = null;
            if (cookieHeader != null) {
                String[] cookies = cookieHeader.split(";");
                for (String cookie : cookies) {
                    String[] cookieParts = cookie.trim().split("=");
                    if (cookieParts.length == 2 && cookieParts[0].trim().equals("session_id")) {
                        sessionId = cookieParts[1].trim();
                        break;
                    }
                }
            }

            System.out.println("Session ID: " + sessionId);
         
            if (pathPart.equals("/login.html") && sessionId == null) {
                sendLoginPage(out);
                return;
            }

            if (pathPart.equals("/login") && method.equals("POST")) {
                char[] content = new char[contentLength];
                in.read(content, 0, contentLength);
                String requestBody = new String(content);
            //System.out.println("Request Body: " + requestBody);

                handleLoginRequest(out, requestBody);
                return;
            }

            if (sessionId == null || !checkSessionValidity(sessionId)) {
                sendRedirectToLoginPage(out);
                return;
            }    
       
            String[] sessionInfo = getSessionInfo(sessionId);
            String userId = sessionInfo[0];
            String userRole = sessionInfo[1];
            boolean isDownload = parts.length > 1 && parts[1].equals("download=true");
            boolean isZipDownload = parts.length > 1 && parts[1].equals("zip=true");

            Path targetPath = Paths.get(HOME_DIR, pathPart).normalize();

            if (!targetPath.startsWith(HOME_DIR)) {
                sendErrorResponse(out, 403, "Forbidden");
                return;
            }

            switch (method) {
                case "GET":
                    handleGetRequest(out, targetPath, pathPart, isDownload, isZipDownload, userId, userRole);
                    break;
                case "POST":
                    char[] content = new char[contentLength];
                    in.read(content, 0, contentLength);
                    String requestBody = new String(content);
                    //System.out.println("Request Body: " + requestBody);
                    handlePostRequest(out, pathPart, requestBody, targetPath, userRole, userId, sessionId);
                    break;
                default:
                    sendErrorResponse(out, 405, "Method Not Allowed");
                    break;
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SQLException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    private void handleFileUploadRequest(OutputStream out, String requestBody, Path targetPath) throws IOException {
        Pattern boundaryPattern = Pattern.compile("^--(\\S+)", Pattern.MULTILINE);
        Matcher matcher = boundaryPattern.matcher(requestBody);
        String boundary = null;
        if (matcher.find()) {
            boundary = matcher.group(1);
        }

        if (boundary == null) {
            System.out.println("Boundary not found in request body");
            return;
        }

        String[] parts = requestBody.split(Pattern.quote("--" + boundary));
        for (String part : parts) {
            if (part.contains("filename=")) {
                Matcher filenameMatcher = Pattern.compile("filename=\"([^\"]+)\"").matcher(part);
                String fileName = null;
                if (filenameMatcher.find()) {
                    fileName = filenameMatcher.group(1);
                }

                if (fileName != null) {
                    int contentStart = part.indexOf("\r\n\r\n") + "\r\n\r\n".length();
                    byte[] fileContent = part.substring(contentStart).getBytes();

                    Path filePath = targetPath.resolve(fileName);
                    Files.write(filePath, fileContent);

                    System.out.println("File uploaded successfully: " + filePath);
                    sendResponse(out, 200, "OK", "text/plain", "File uploaded successfully\n".getBytes());
        
                }
            }
        }
    }
    private void handlePostRequest(OutputStream out, String pathPart, String requestBody, Path targetPath, String userRole, String userId, String sessionId) throws IOException {
        if (pathPart.equals("/save") && (userRole.equals("2") || userRole.equals("1"))) {
            handleSaveRequest(out, requestBody);
        } else if (pathPart.equals("/logout")) {
            handleLogoutRequest(out, sessionId);
        } else if (pathPart.equals("/createUser") && userRole.equals("1")) {
            handleCreateUserRequest(out, requestBody);
        } else if (pathPart.equals("/addPath") && userRole.equals("1")) {
            handleAddPathRequest(out, requestBody);
        } else {
            if (!targetPath.startsWith(HOME_DIR)) {
                sendErrorResponse(out, 403, "Forbidden");
            }
        }
    }

    private void handleCreateUserRequest(OutputStream out, String requestBody) throws IOException {
    
        Map<String, String> formData = parseFormData(requestBody);

        String username = formData.get("username");
        String password = formData.get("password");
        String roleName = formData.get("roleName");
        String filePath = formData.get("filePath");

        System.out.println("Username: " + username);
        System.out.println("Password: " + password);
        System.out.println("Role: " + roleName);
        System.out.println("Directory: " + filePath);
        File file = new File(filePath);
        if (!file.exists()) {
            sendErrorResponse(out, 400, "File path does not exist");
            return;
        }

        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            int roleId = -1;
            try (PreparedStatement stmt = conn.prepareStatement("SELECT role_id FROM Roles WHERE role_name = ?")) {
                stmt.setString(1, roleName);
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    roleId = rs.getInt("role_id");
                }
            }

            if (roleId == -1) {
                sendErrorResponse(out, 400, "Role does not exist");
                return;
            }

            try (PreparedStatement insertUserStmt = conn.prepareStatement("INSERT INTO Users (username, password, role_id) VALUES (?, ?, ?)",                                                                 Statement.RETURN_GENERATED_KEYS)) {
                insertUserStmt.setString(1, username);
                insertUserStmt.setString(2, password);
                insertUserStmt.setInt(3, roleId);
                insertUserStmt.executeUpdate();

                ResultSet generatedKeys = insertUserStmt.getGeneratedKeys();
                int userId = -1;
                if (generatedKeys.next()) {
                    userId = generatedKeys.getInt(1);
                }
                try (PreparedStatement insertPathStmt = conn.prepareStatement("INSERT INTO Paths (user_id, path) VALUES (?, ?)")) {
                    insertPathStmt.setInt(1, userId);
                    insertPathStmt.setString(2, filePath);
                    insertPathStmt.executeUpdate();
                }
            }

            sendResponse(out, 200, "OK", "text/plain", "User created successfully\n".getBytes());
        } catch (SQLException e) {
            e.printStackTrace();
            sendErrorResponse(out, 500, "Internal Server Error");
        }
    }

    private void handleAddPathRequest(OutputStream out, String requestBody) throws IOException {
    
        System.out.println("Received Form Data: " + requestBody);

        Map<String, String> formData = parseFormData(requestBody);

        String userIdStr = formData.get("userId");
        String username = formData.get("username");
        String filePath = formData.get("filePath");

        System.out.println("User ID: " + userIdStr);
        System.out.println("Username: " + username);
        System.out.println("Directory: " + filePath);

        int userId;
        try {
            userId = Integer.parseInt(userIdStr);
        } catch (NumberFormatException e) {
            sendErrorResponse(out, 400, "Invalid User ID");
            return;
         }

        File file = new File(filePath);
        if (!file.exists()) {
            sendErrorResponse(out, 400, "File path does not exist");
            return;
        }

        try (Connection conn = DriverManager.getConnection(DB_URL)) {
       
            try (PreparedStatement checkUserStmt = conn.prepareStatement("SELECT user_id FROM Users WHERE user_id = ?")) {
                checkUserStmt.setInt(1, userId);
                ResultSet rs = checkUserStmt.executeQuery();
                if (!rs.next()) {
                    sendErrorResponse(out, 400, "User ID does not exist");
                    return;
                }
            }

            try (PreparedStatement insertPathStmt = conn.prepareStatement("INSERT INTO Paths (user_id, path) VALUES (?, ?)")) {
                insertPathStmt.setInt(1, userId);
                insertPathStmt.setString(2, filePath);
                insertPathStmt.executeUpdate();
            }

            sendResponse(out, 200, "OK", "text/plain", "Path added successfully\n".getBytes());
        } catch (SQLException e) {
            e.printStackTrace();
            sendErrorResponse(out, 500, "Internal Server Error");
        }
    }

    private void handleGetRequest(OutputStream out, Path targetPath, String pathPart, boolean isDownload, boolean isZipDownload, String userId, String userRole) throws IOException, SQLException {    
            
        if(pathPart.equals("/login.html")){
            switch (userRole) {
                case "1": // Admin
                    sendAdminPage(out);
                    break;
                default:
                    String response = generateDirectoryListing(Paths.get(HOME_DIR), "/", userRole, userId);
                    sendResponse(out, 200, "OK", "text/html", response.getBytes());
                    break;
            }
        }
        if ("1".equals(userRole)){
            switch (pathPart) {
                case "/admin.html":
                    sendAdminPage(out);
                    break;
                case "/getUserList":
                    fetchUserList(out);
                    return;
                case "/manage_users":
                    Path manageUsersFilePath = Paths.get("D:/manage_users.html"); // Update the path as per your file location
                    byte[] manageUsersContent = Files.readAllBytes(manageUsersFilePath);
                    String modifiedHtml = new String(manageUsersContent, StandardCharsets.UTF_8);
                    sendResponse(out, 200, "OK", "text/html", modifiedHtml.getBytes());
                    break;
                default:
                    break;
            }
                
        }
        if (pathPart.equals("/file_explorer") || pathPart.equals("/") || pathPart.isEmpty()) {
            String response = generateDirectoryListing(Paths.get(HOME_DIR), "/", userRole, userId);
            sendResponse(out, 200, "OK", "text/html", response.getBytes());
        }else {
            if (Files.isDirectory(targetPath)) {
                if (isZipDownload) {
                    sendZipResponse(out, targetPath);
                } else {
                    String response = generateDirectoryListing(targetPath, pathPart, userRole, userId);
                    sendResponse(out, 200, "OK", "text/html", response.getBytes());
                }
            } else if (Files.isRegularFile(targetPath)) {
                if (isDownload) {
                    sendDownloadResponse(out, targetPath);
                } else {
                    System.out.println(targetPath);
                    String filePath= targetPath.toString().replace("\\", "/");
                    boolean hasPermission = checkPathPermission(filePath, userId);
                    if(userRole.equals("1")){
                        hasPermission = true;
                    }
                    System.out.println(hasPermission);
                        if(hasPermission){
                            if (isTextFile(targetPath)) {
                                sendEditorResponse(out, targetPath);
                            } else if (isImageFile(targetPath)) {
                                sendImageEditorPage(out, targetPath);
                            }else {
                                sendFileResponse(out, targetPath);
                            }
                        } else{
                            sendErrorResponse(out, 404, "Do not have access");
                        }
                    
                    
                }    
            } else {
                sendErrorResponse(out, 404, "Not Found");
            }
        }
    }
    
    /*private void sendStaticFileResponse(String fileName, OutputStream out) throws IOException {
    Path filePath = Paths.get("D:/", fileName); // Update the path to your static folder
    if (Files.exists(filePath) && Files.isRegularFile(filePath)) {
        byte[] fileContent = Files.readAllBytes(filePath);
        String contentType = Files.probeContentType(filePath);
        sendResponse(out, 200, "OK", contentType, fileContent);
    } else {
        sendErrorResponse(out, 404, "Not Found");
    }
    }*/
    private boolean isTextFile(Path path) throws IOException {
        String mimeType = Files.probeContentType(path);
        return mimeType != null && mimeType.startsWith("text");
    }
    
    private void sendLoginPage(OutputStream out) throws IOException {
        byte[] loginPageContent = Files.readAllBytes(Paths.get("D:/login.html"));
        sendResponse(out, 200, "OK", "text/html", loginPageContent);
    }

    private void sendAdminPage(OutputStream out) throws IOException {
        byte[] adminPageContent = Files.readAllBytes(Paths.get("D:/admin.html"));
        sendResponse(out, 200, "OK", "text/html", adminPageContent);
    }
    private void sendRedirectToLoginPage(OutputStream out) throws IOException {
        PrintWriter writer = new PrintWriter(out, false);
        writer.print("HTTP/1.1 302 Found\r\n");
        writer.print("Location: /login.html\r\n");
        writer.print("Connection: close\r\n");
        writer.print("\r\n");
        writer.flush();
    }
    private void sendEditorResponse(OutputStream out, Path filePath) throws IOException {
        byte[] fileContent = Files.readAllBytes(filePath);
        String fileContentStr = new String(fileContent);

        String editorTemplate = new String(Files.readAllBytes(Paths.get("D:/editor.html")));
        String response = editorTemplate
            .replace("{{file_content}}", escapeHtml(fileContentStr))
            .replace("{{filepath}}", filePath.toString());

        sendResponse(out, 200, "OK", "text/html", response.getBytes());
    }
    
    private String escapeHtml(String s) {
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }
    private void handleLoginRequest(OutputStream out, String requestBody) throws IOException {
        String[] params = requestBody.split("&");
        String username = null;
        String password = null;
        for (String param : params) {
            String[] pair = param.split("=");
            if (pair[0].equals("username")) {
                username = pair[1];
            } else if (pair[0].equals("password")) {
                password = pair[1];
            }
        }

        try (Connection conn = DriverManager.getConnection(DB_URL);
            PreparedStatement stmt = conn.prepareStatement("SELECT u.user_id, u.password, r.role_name FROM Users u JOIN Roles r ON u.role_id = r.role_id WHERE u.username = ?")) {
            stmt.setString(1, username);

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                int userId = rs.getInt("user_id");
                String storedPassword = rs.getString("password");
                String role = rs.getString("role_name");

                if (password.equals(storedPassword)) {
                    String sessionId = generateSessionId();
                    long currentTime = System.currentTimeMillis();

                    try (PreparedStatement insertStmt = conn.prepareStatement("INSERT INTO sessions (id, user_id, creation_time, last_access_time) VALUES (?, ?, ?, ?)")) {
                        insertStmt.setString(1, sessionId);
                        insertStmt.setInt(2, userId);
                        insertStmt.setLong(3, currentTime);
                        insertStmt.setLong(4, currentTime);
                        insertStmt.executeUpdate();
                    }
                //sendSessionCookie(out, sessionId);

                    switch (role) {
                        case "admin":
                            sendRedirectWithCookie(out, "/admin.html", sessionId);
                            break;
                        case "technician":
                            sendRedirectWithCookie(out, "/file_explorer", sessionId);
                            break;
                        case "guest":
                            sendRedirectWithCookie(out, "/file_explorer", sessionId);
                            break;
                        default:
                            sendErrorResponse(out, 403, "Forbidden");
                            break;
                    }
                } else {
                    sendErrorResponse(out, 401, "Unauthorized");
                }
            } else {
                sendErrorResponse(out, 401, "Unauthorized");
            }
        } catch (SQLException e) {
            e.printStackTrace();
            sendErrorResponse(out, 500, "Internal Server Error");
        }
    }

    private Map<String, String> parseFormData(String requestBody) {
        Map<String, String> formData = new HashMap<>();
        String[] pairs = requestBody.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=");
            String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
            String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
            formData.put(key, value);
        }
        return formData;
    }


         
    private void sendRedirect(OutputStream out, String redirectURI, String redirectMethod) throws IOException {
        String response = "HTTP/1.1 302 Found\r\n";
        response += "Location: " + redirectURI + "\r\n";
        if (redirectMethod != null && !redirectMethod.isEmpty()) {
            response += "Location: " + redirectMethod + "\r\n";
        }
        response += "Connection: close\r\n";
        response += "\r\n";
        out.write(response.getBytes());
    }
    private void handleSaveRequest( OutputStream out, String requestBody) throws IOException {        
        String[] requestParts = requestBody.split("###", 2);
        if (requestParts.length < 2) {
            sendErrorResponse(out, 400, "Invalid request format\n"); // Bad Request
            return;
        }

        String filePath = requestParts[0].trim();
        String content = requestParts[1];
        
        filePath = Paths.get(filePath).toString();

        File file = new File(filePath);
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }

        Files.write(Paths.get(filePath), content.getBytes());

        sendResponse(out, 200, "OK", "text/plain", "File saved successfully\n".getBytes());
    }



    private void sendResponse(OutputStream out, int statusCode, String statusMessage, String contentType, byte[] content) throws IOException {
        PrintWriter writer = new PrintWriter(out, false);
        writer.printf("HTTP/1.1 %d %s\r\n", statusCode, statusMessage);
        writer.printf("Content-Type: %s\r\n", contentType);
        writer.printf("Content-Length: %d\r\n", content.length);
        writer.printf("\r\n");
        writer.flush();
        out.write(content);
        out.flush();
    }

    private void sendErrorResponse(OutputStream out, int statusCode, String statusMessage) throws IOException {
        String response = "<html><body><h1>" + statusMessage + "</h1></body></html>";
        sendResponse(out, statusCode, statusMessage, "text/html", response.getBytes());
    }

    private void sendFileResponse(OutputStream out, Path filePath) throws IOException {
        byte[] fileContent = Files.readAllBytes(filePath);
        String contentType = Files.probeContentType(filePath);
        sendResponse(out, 200, "OK", contentType, fileContent);
    }

    private void sendDownloadResponse(OutputStream out, Path filePath) throws IOException {
        byte[] fileContent = Files.readAllBytes(filePath);
        String fileName = filePath.getFileName().toString();
        PrintWriter writer = new PrintWriter(out, false);
        writer.printf("HTTP/1.1 200 OK\r\n");
        writer.printf("Content-Type: application/octet-stream\r\n");
        writer.printf("Content-Disposition: attachment; filename=\"%s\"\r\n", fileName);
        writer.printf("Content-Length: %d\r\n", fileContent.length);
        writer.printf("\r\n");
        writer.flush();
        out.write(fileContent);
        out.flush();
    }

    private void sendZipResponse(OutputStream out, Path dirPath) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (ZipOutputStream zipOutputStream = new ZipOutputStream(byteArrayOutputStream)) {
            Files.walk(dirPath).forEach(path -> {
                ZipEntry zipEntry = new ZipEntry(dirPath.relativize(path).toString());
                if (Files.isDirectory(path)) {
                    zipEntry = new ZipEntry(zipEntry.getName() + "/");
                }
                try {
                    zipOutputStream.putNextEntry(zipEntry);
                    if (Files.isRegularFile(path)) {
                        Files.copy(path, zipOutputStream);
                    }
                    zipOutputStream.closeEntry();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        }
        byte[] zipContent = byteArrayOutputStream.toByteArray();
        String zipFileName = dirPath.getFileName().toString() + ".zip";
        PrintWriter writer = new PrintWriter(out, false);
        writer.printf("HTTP/1.1 200 OK\r\n");
        writer.printf("Content-Type: application/zip\r\n");
        writer.printf("Content-Disposition: attachment; filename=\"%s\"\r\n", zipFileName);
        writer.printf("Content-Length: %d\r\n", zipContent.length);
        writer.printf("\r\n");
        writer.flush();
        out.write(zipContent);
        out.flush();
    }

    private void sendImageEditorPage(OutputStream out, Path filePath) throws IOException {
       byte[] fileContent = Files.readAllBytes(filePath);
        String base64Image = Base64.getEncoder().encodeToString(fileContent);
        String editorTemplate = new String(Files.readAllBytes(Paths.get("D:/imageeditor.html")));
        String response = editorTemplate.replace("{{base64_image}}", base64Image);        
        sendResponse(out, 200, "OK", "text/html", response.getBytes());
    }
    private boolean isImageFile(Path filePath) throws IOException {
        String mimeType = Files.probeContentType(filePath);
        return mimeType != null && mimeType.startsWith("image");
    }

        private String generateDirectoryListing(Path dirPath, String requestURI, String userRole, String userId) throws IOException, SQLException {
            String template = new String(Files.readAllBytes(Paths.get("D:/fileexplorer.html")));

            StringBuilder fileListBuilder = new StringBuilder();

            String parentURI = getParentURI(requestURI);

            if (!dirPath.equals(Paths.get(HOME_DIR))) {
                fileListBuilder.append("<li><a href=\"").append(parentURI).append("\">..</a></li>");
            }

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dirPath)) {
            for (Path entry : stream) {
                String fileName = entry.getFileName().toString();
                String filePath = Paths.get(requestURI).resolve(fileName).normalize().toString();
                
            //System.out.println(HOME_DIR);
                if (Files.isDirectory(entry)) {
                    fileListBuilder.append("<li><a href=\"").append(filePath).append("/\">").append(fileName).append("/</a></li>");
                } else {
                    String normalizedFilePath = Paths.get(requestURI).resolve(filePath).normalize().toString();
                    normalizedFilePath = normalizedFilePath.replace("\\", "/");
                
                    normalizedFilePath = HOME_DIR + normalizedFilePath;
                //System.out.println(normalizedFilePath);
                    Path homeDirPath = Paths.get(HOME_DIR);
                    Path normalizedPathObject = Paths.get(normalizedFilePath);
                    Path combinedPath = homeDirPath.resolve(normalizedPathObject).normalize();
                    String finalPath;
                    finalPath = combinedPath.toString().replace("\\", "/");
                //System.out.println(finalPath);
                //System.out.println(userRole);
                    boolean hasPermission = checkPathPermission(finalPath, userId);
                    if("1".equals(userRole)){
                        fileListBuilder.append("<li class='file' data-href='").append(filePath).append("'>").append(fileName).append("</li>");

                    }else {
                        if (hasPermission) {
                            fileListBuilder.append("<li class='file' data-href='").append(filePath).append("'>").append(fileName).append("</li>");
                        } else {
                            fileListBuilder.append("<li>").append(fileName).append("</li>");
                        }
                    }
                
                
                }
            }
        }
        String fileList = fileListBuilder.toString();
        String response = template.replace("{{requestURI}}", requestURI).replace("{{fileList}}", fileList);
        return response;
    }

    private String getParentURI(String requestURI) {
        if (requestURI.equals("/") || requestURI.equals("")) {
            return "/";
        }
        if (requestURI.endsWith("/")) {
            requestURI = requestURI.substring(0, requestURI.length() - 1);
        }
        int lastSlashIndex = requestURI.lastIndexOf("/");
        if (lastSlashIndex <= 0) {
            return "/";
        }
            
        return requestURI.substring(0, lastSlashIndex) + "/";
    }
    private void fetchUserList(OutputStream out) throws IOException {
        List<Map<String, String>> userList = new ArrayList<>();

        String query = "SELECT Users.user_id, Users.username, Roles.role_name, Paths.path " +
                       "FROM Users " +
                       "JOIN Roles ON Users.role_id = Roles.role_id " +
                       "JOIN Paths ON Users.user_id = Paths.user_id";

        try (Connection conn = DriverManager.getConnection(DB_URL);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query)) {

            while (rs.next()) {
                Map<String, String> user = new HashMap<>();
                user.put("userId", String.valueOf(rs.getInt("user_id")));
                user.put("username", rs.getString("username"));
                user.put("roleName", rs.getString("role_name"));
                user.put("filePath", rs.getString("path"));
                userList.add(user);
            }

            String userListJson = buildJson(userList);

            sendResponse(out, 200, "OK", "application/json", userListJson.getBytes());
        } catch (SQLException e) {
            e.printStackTrace();
            sendErrorResponse(out, 500, "Internal Server Error");
        }
    }

    private String buildJson(List<Map<String, String>> userList) {
        StringBuilder json = new StringBuilder();
        json.append("[");
        for (int i = 0; i < userList.size(); i++) {
            Map<String, String> user = userList.get(i);
            json.append("{");
            json.append("\"userId\":").append("\"").append(user.get("userId")).append("\",");
            json.append("\"username\":").append("\"").append(user.get("username")).append("\",");
            json.append("\"roleName\":").append("\"").append(user.get("roleName")).append("\",");
            json.append("\"filePath\":").append("\"").append(user.get("filePath")).append("\"");
            json.append("}");
            if (i < userList.size() - 1) {
                json.append(",");
            }
        }
        json.append("]");
        return json.toString();
    }

    private String generateSessionId() {
        return UUID.randomUUID().toString();
    }
 
    private void sendRedirectWithCookie(OutputStream out, String location, String sessionId) throws IOException {    
        PrintWriter writer = new PrintWriter(out, false);
        writer.print("HTTP/1.1 302 Found\r\n");
        writer.printf("Location:%s\r\n",  location);
        writer.printf("Set-Cookie: session_id=%s; Path=/\r\n", sessionId);
        writer.print("Content-Length: 0\r\n");
        writer.print("\r\n");
        writer.flush();
    }
    private boolean checkSessionValidity(String sessionId) {
        boolean isValid = false;
        try (Connection conn = DriverManager.getConnection(DB_URL);
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM sessions WHERE id = ?")) {
            stmt.setString(1, sessionId);
            try (ResultSet rs = stmt.executeQuery()) {
                isValid = rs.next(); // If the ResultSet has at least one row, the session ID is valid
            }
        } catch (SQLException e) {
            e.printStackTrace(); // Handle database connection or query errors
        }
        return isValid;
    }
    public String[] getSessionInfo(String sessionId) throws SQLException {

        try (Connection connection = DriverManager.getConnection(DB_URL);
             Statement statement = connection.createStatement()) {
            String[] sessionInfo = new String[2]; // Create an array to hold userId and roleId

        String getUserIdQuery = "SELECT user_id FROM sessions WHERE id = '" + sessionId + "'";
        ResultSet resultSet = statement.executeQuery(getUserIdQuery);
        if (resultSet.next()) {
            int userId = resultSet.getInt("user_id");
            sessionInfo[0] = String.valueOf(userId); 

            String getRoleIdQuery = "SELECT role_id FROM Users WHERE user_id = " + userId;
            ResultSet roleResultSet = statement.executeQuery(getRoleIdQuery);
            if (roleResultSet.next()) {
                int roleId = roleResultSet.getInt("role_id");
                sessionInfo[1] = String.valueOf(roleId); // Store roleId in array
            }
        }

        return sessionInfo; 
        }
    }
    private boolean checkPathPermission(String filePath, String userIdStr) throws SQLException {
        int userId = Integer.parseInt(userIdStr);
    
        try (Connection connection = DriverManager.getConnection(DB_URL);
        Statement statement = connection.createStatement()) {
        String checkPathQuery = "SELECT COUNT(*) AS count FROM Paths WHERE path = '" + filePath + "' AND user_id = " + userId;
        ResultSet resultSet = statement.executeQuery(checkPathQuery);
        if (resultSet.next()) {
            int count = resultSet.getInt("count");
            return count > 0; }
        }
        return false; // Default to false if an error occurs or path doesn't exist
    }
    private void handleLogoutRequest(OutputStream out, String sessionId) throws IOException {
        invalidateSession(sessionId);

        sendClearSessionAndRedirect(out, "/");
    }

    private void invalidateSession(String sessionId) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
            PreparedStatement stmt = conn.prepareStatement("DELETE FROM sessions WHERE id = ?")) {
            stmt.setString(1, sessionId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace(); // Handle database connection or query errors
        }
    }


    private void sendClearSessionAndRedirect(OutputStream out, String redirectURI) throws IOException {
        PrintWriter writer = new PrintWriter(out, false);
        writer.print("HTTP/1.1 302 Found\r\n");
        writer.print("Location: " + redirectURI + "\r\n"); // Redirect to the home page or any other desired page
        writer.print("Set-Cookie: session_id=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n"); // Delete the session cookie
        writer.print("Connection: close\r\n");
        writer.print("\r\n");
        writer.flush();
    }

    }
}

