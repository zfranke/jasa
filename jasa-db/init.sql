use jasa;

-- Create user table
CREATE TABLE IF NOT EXISTS users (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    PRIMARY KEY (id)
);

-- Create the 'results' table for storing survey responses
CREATE TABLE IF NOT EXISTS results (
    result_id INT AUTO_INCREMENT PRIMARY KEY,
    response_datetime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    survey_id INT NOT NULL,
    choice ENUM('happy', 'neutral', 'angry') NOT NULL,
    FOREIGN KEY (survey_id) REFERENCES surveys(survey_id)
);