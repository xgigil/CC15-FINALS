CREATE DATABASE  IF NOT EXISTS `users` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci */;
USE `users`;
-- MySQL dump 10.13  Distrib 8.0.42, for Win64 (x86_64)
--
-- Host: localhost    Database: users
-- ------------------------------------------------------
-- Server version	5.5.5-10.4.32-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `accounts`
--

DROP TABLE IF EXISTS `accounts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `accounts` (
  `user_id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password` text DEFAULT NULL,
  `role` enum('Admin','Executive','Member') NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_login` timestamp NULL DEFAULT NULL,
  `status` enum('Active','Inactive','Pending') DEFAULT 'Pending',
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `username` (`username`),
  KEY `idx_accounts_username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=22 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `accounts`
--

LOCK TABLES `accounts` WRITE;
/*!40000 ALTER TABLE `accounts` DISABLE KEYS */;
INSERT INTO `accounts` VALUES (2,'bgil','$2b$12$SGyu2wEsXVU3XFLxKIUzSOp7ihxBEBdpEjoxAjzg/0Dgar8mAK1V6','Executive','2025-05-18 11:49:16','2025-05-18 20:08:19','Active'),(5,'bloi','$2b$12$ZEOaGAPakflI6/0cHNgz/Olbyu10nC2ZEhmYUAx9gNLyoiA4jaKr.','Member','2025-05-18 12:26:40','2025-05-18 20:08:40','Active'),(11,'hello','$2b$12$oJOZXiNwup0YeaIVHV.ZmOip5aEX6lgdzUSJTXFCw7RA8ZZ676yb2','Member','2025-05-18 13:36:09','2025-05-18 13:36:14','Active'),(14,'chitloks','$2b$12$MGLFMfsK5NvmvwzJiWwKz.HoKcoczFwVzVF5NwV40aq.6fEZtTZ4G','Member','2025-05-18 15:49:23','2025-05-18 17:05:40','Active'),(16,'asdasd','$2b$12$PKndDDfWMZ7jzOoEvAwanOY5e9hAVsTxR1grFKgsjfGddAqUEXbza','Executive','2025-05-18 19:02:00',NULL,'Inactive'),(17,'admin','$2b$12$0.sAAjL0FGtMp8oQFpxPs.K7Bm0vcDk5NL3AX/VYbKKIc8E3v9mlq','Admin','2025-05-18 19:02:42','2025-05-21 09:17:53','Active'),(20,'admin_2','$2b$12$qaohteZyYL9GxfyrDmgbSOYQmspPYn0JVnbYh3lUVe3bsqXVBmxHe','Admin','2025-05-21 09:03:11','2025-05-21 09:16:30','Active'),(21,'bgiloks','$2b$12$a9yRfO1VUy8cy71J6l7lXuJDhyU5a/l2YE.xFZfbXMqbxVhE2Qtf6','Member','2025-05-21 09:18:20','2025-05-21 09:18:35','Active');
/*!40000 ALTER TABLE `accounts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `confirmation_approvals`
--

DROP TABLE IF EXISTS `confirmation_approvals`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `confirmation_approvals` (
  `approval_id` int(11) NOT NULL AUTO_INCREMENT,
  `request_id` int(11) NOT NULL,
  `approved_by` int(11) NOT NULL,
  `approved_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`approval_id`),
  KEY `request_id` (`request_id`),
  KEY `approved_by` (`approved_by`),
  CONSTRAINT `confirmation_approvals_ibfk_1` FOREIGN KEY (`request_id`) REFERENCES `confirmation_requests` (`request_id`),
  CONSTRAINT `confirmation_approvals_ibfk_2` FOREIGN KEY (`approved_by`) REFERENCES `accounts` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `confirmation_approvals`
--

LOCK TABLES `confirmation_approvals` WRITE;
/*!40000 ALTER TABLE `confirmation_approvals` DISABLE KEYS */;
INSERT INTO `confirmation_approvals` VALUES (1,6,2,'2025-05-18 17:01:38'),(2,9,2,'2025-05-18 17:05:30'),(6,10,2,'2025-05-18 19:03:18');
/*!40000 ALTER TABLE `confirmation_approvals` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `confirmation_requests`
--

DROP TABLE IF EXISTS `confirmation_requests`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `confirmation_requests` (
  `request_id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `request_type` enum('Registration','Deletion') NOT NULL,
  `status` enum('Pending','Approved','Rejected') DEFAULT 'Pending',
  `requested_by` int(11) DEFAULT NULL,
  `requested_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`request_id`),
  KEY `user_id` (`user_id`),
  KEY `requested_by` (`requested_by`),
  KEY `idx_requests_status` (`status`),
  CONSTRAINT `confirmation_requests_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `accounts` (`user_id`),
  CONSTRAINT `confirmation_requests_ibfk_2` FOREIGN KEY (`requested_by`) REFERENCES `accounts` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `confirmation_requests`
--

LOCK TABLES `confirmation_requests` WRITE;
/*!40000 ALTER TABLE `confirmation_requests` DISABLE KEYS */;
INSERT INTO `confirmation_requests` VALUES (4,5,'Deletion','Pending',5,'2025-05-18 13:25:19'),(5,5,'Deletion','Pending',5,'2025-05-18 13:35:13'),(6,11,'Registration','Rejected',11,'2025-05-18 13:36:09'),(7,5,'Deletion','Pending',5,'2025-05-18 14:05:10'),(8,2,'Deletion','Pending',2,'2025-05-18 15:30:15'),(9,14,'Registration','Approved',14,'2025-05-18 15:49:23'),(10,16,'Registration','Rejected',16,'2025-05-18 19:02:00'),(11,21,'Deletion','Pending',21,'2025-05-21 09:18:44');
/*!40000 ALTER TABLE `confirmation_requests` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `profiles`
--

DROP TABLE IF EXISTS `profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `profiles` (
  `profile_id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `first_name` varchar(255) NOT NULL,
  `middle_name` varchar(255) DEFAULT NULL,
  `last_name` varchar(255) NOT NULL,
  `email` varchar(255) DEFAULT NULL,
  `contact_number` varchar(20) DEFAULT NULL,
  `department` varchar(100) DEFAULT NULL,
  `position` varchar(100) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`profile_id`),
  UNIQUE KEY `user_id` (`user_id`),
  KEY `idx_profiles_user` (`user_id`),
  CONSTRAINT `profiles_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `accounts` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `profiles`
--

LOCK TABLES `profiles` WRITE;
/*!40000 ALTER TABLE `profiles` DISABLE KEYS */;
INSERT INTO `profiles` VALUES (1,2,'GAIL','NATINDIM','LOKING',NULL,NULL,NULL,NULL,'2025-05-18 11:49:16','2025-05-18 11:49:16'),(3,5,'LOISSE','NATINDIM','LOKING',NULL,NULL,NULL,NULL,'2025-05-18 12:26:41','2025-05-18 12:26:41'),(8,11,'SI','GAIL','KO',NULL,NULL,'','','2025-05-18 13:36:09','2025-05-21 08:48:05'),(9,14,'CHITO','ARABALA','LOKING',NULL,NULL,NULL,NULL,'2025-05-18 15:49:23','2025-05-18 15:49:23'),(10,16,'ASDASD','ASDASD','ASDASD',NULL,NULL,NULL,NULL,'2025-05-18 19:02:00','2025-05-18 19:02:00'),(11,17,'ADMIN','ADMIN','ADMIN',NULL,NULL,NULL,NULL,'2025-05-18 19:02:42','2025-05-18 19:02:42'),(12,20,'ADMIN','ADMIN','ADMIN',NULL,NULL,NULL,NULL,'2025-05-21 09:03:11','2025-05-21 09:03:11'),(13,21,'GAIL','LOKING','NATINDIM',NULL,NULL,NULL,NULL,'2025-05-21 09:18:20','2025-05-21 09:18:20');
/*!40000 ALTER TABLE `profiles` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-05-21 17:43:19
