package com.example.demoOAuth.helper;

import com.example.demoOAuth.dto.UserRegistrationRequest;
import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvException;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Helper {

    private static final Logger logger = LoggerFactory.getLogger(Helper.class);

    // check that file is of excel file or not
    public static boolean checkExcelFormat(MultipartFile file){
        String contentType = file.getContentType();

        if(contentType.equals("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")){
            logger.info("File format is valid Excel format.");
            return true;
        }else{
            logger.warn("File format is invalid. Expected: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            return false;
        }
    }

    // check that file is of CSV format or not
    public static boolean checkCSVFormat(MultipartFile file){
        String contentType = file.getContentType();
        
        if(contentType.equals("text/csv") || contentType.equals("application/csv")){
            logger.info("File format is valid CSV format.");
            return true;
        }else{
            logger.warn("File format is invalid. Expected: text/csv or application/csv");
            return false;
        }
    }

    // check if file is either Excel or CSV
    public static boolean checkFileFormat(MultipartFile file){
        return checkExcelFormat(file) || checkCSVFormat(file);
    }

    // converts excel to list of UserRegistrationRequest
    public static List<UserRegistrationRequest> convertExcelToListOfUserRegistrationRequest(InputStream is) throws IOException {
        List<UserRegistrationRequest> list = new ArrayList<>();

        try (XSSFWorkbook workbook = new XSSFWorkbook(is)) {
            // Get the first sheet
            XSSFSheet sheet = workbook.getSheetAt(0);

            if (sheet == null) {
                return list;
            }

            int rowNumber = 0;
            Iterator<Row> iterator = sheet.iterator();

            while (iterator.hasNext()) {
                Row row = iterator.next();
                if (rowNumber == 0) {
                    rowNumber++;
                    continue; // Skip header row
                }

                Iterator<Cell> cells = row.iterator();
                int cid = 0;

                UserRegistrationRequest userRequest = new UserRegistrationRequest();
                boolean isValidUser = true;

                String username = null, email = null, firstName = null, lastName = null, password = null, role = null;

                while (cells.hasNext()) {
                    Cell cell = cells.next();
                    try {
                        switch (cid) {
                            case 0: // username
                                username = cell.getStringCellValue().trim();
                                break;
                            case 1: // email
                                email = cell.getStringCellValue().trim();
                                break;
                            case 2: // firstName
                                firstName = cell.getStringCellValue().trim();
                                break;
                            case 3: // lastName
                                lastName = cell.getStringCellValue().trim();
                                break;
                            case 4: // password
                                password = cell.getStringCellValue().trim();
                                break;
                            case 5: // role
                                role = cell.getStringCellValue().toLowerCase().trim();
                                if (!role.equals("user") && !role.equals("employee")) {
                                    logger.error("Invalid role at row {}: {}. Must be 'user' or 'employee'", row.getRowNum(), role);
                                    isValidUser = false;
                                }
                                break;
                            default:
                                break;
                        }
                    } catch (Exception e) {
                        logger.error("Error reading cell at row {}, column {}: {}", row.getRowNum(), cid, e.getMessage());
                        isValidUser = false;
                    }
                    cid++;
                }

                if (isValidUser && username != null && email != null && firstName != null && 
                    lastName != null && password != null && role != null) {
                    
                    userRequest.setUsername(username);
                    userRequest.setEmail(email);
                    userRequest.setFirstName(firstName);
                    userRequest.setLastName(lastName);
                    userRequest.setPassword(password);
                    userRequest.setRole(role);
                    
                    list.add(userRequest);
                } else {
                    logger.warn("Skipping invalid user at row {}: missing required fields", row.getRowNum());
                }
            }

        } catch (Exception e) {
            logger.error("Error processing Excel file: {}", e.getMessage());
            throw new IOException("Failed to process Excel file", e);
        }
        return list;
    }

    // converts CSV to list of UserRegistrationRequest
    public static List<UserRegistrationRequest> convertCSVToListOfUserRegistrationRequest(InputStream is) throws IOException {
        List<UserRegistrationRequest> list = new ArrayList<>();
        
        try (CSVReader csvReader = new CSVReader(new InputStreamReader(is))) {
            List<String[]> records = csvReader.readAll();
            
            // Skip header row if present
            boolean isFirstRow = true;
            
            for (String[] record : records) {
                if (isFirstRow) {
                    isFirstRow = false;
                    // Check if first row contains headers
                    if (record.length > 0 && record[0].toLowerCase().contains("username")) {
                        continue; // Skip header row
                    }
                }
                
                if (record.length >= 6) { // Ensure we have all required fields
                    UserRegistrationRequest userRequest = new UserRegistrationRequest();
                    boolean isValidUser = true;
                    
                    try {
                        // CSV format: username, email, firstName, lastName, password, role
                        userRequest.setUsername(record[0].trim());
                        userRequest.setEmail(record[1].trim());
                        userRequest.setFirstName(record[2].trim());
                        userRequest.setLastName(record[3].trim());
                        userRequest.setPassword(record[4].trim());
                        
                        String role = record[5].trim().toLowerCase();
                        if (!role.equals("user") && !role.equals("employee")) {
                            logger.error("Invalid role in CSV: {}. Must be 'user' or 'employee'", role);
                            isValidUser = false;
                        } else {
                            userRequest.setRole(role);
                        }
                        
                    } catch (Exception ex) {
                        logger.error("Error parsing CSV row: {}", String.join(",", record));
                        isValidUser = false;
                    }
                    
                    if (isValidUser) {
                        list.add(userRequest);
                    }
                } else {
                    logger.error("Insufficient data in CSV row (expected 6 columns): {}", String.join(",", record));
                }
            }
            
        } catch (CsvException e) {
            logger.error("Error reading CSV file: {}", e.getMessage());
            throw new IOException("Failed to process CSV file", e);
        }
        
        return list;
    }
}
