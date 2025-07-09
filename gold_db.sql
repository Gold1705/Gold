USE sql5788528;

SET FOREIGN_KEY_CHECKS=0;

-- TABLE: users
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(100) NOT NULL,
  `email` VARCHAR(100) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `role` ENUM('user','admin') NOT NULL DEFAULT 'user',
  `invitation_code` VARCHAR(50) DEFAULT NULL,
  `referred_by` INT(11) DEFAULT NULL,
  `referral_bonus_paid` TINYINT(1) NOT NULL DEFAULT 0,
  `is_confirmed` TINYINT(1) DEFAULT 1,
  `confirmation_token` VARCHAR(255) DEFAULT NULL,
  `wallet_address` VARCHAR(255) DEFAULT NULL,
  `referral_code` VARCHAR(255) DEFAULT NULL,
  `referrer_id` INT(11) DEFAULT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `balance_fcf` DECIMAL(15,2) NOT NULL DEFAULT 0.00,
  `profile_image_url` VARCHAR(255) DEFAULT '/assets/img/default-profile.png',
  PRIMARY KEY (`id`),
  UNIQUE KEY `email_unique` (`email`(100)),
  UNIQUE KEY `referral_code_unique` (`referral_code`(100)),
  KEY `fk_referred_by` (`referred_by`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- TABLE: investments
DROP TABLE IF EXISTS `investments`;
CREATE TABLE `investments` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `user_id` INT(11) NOT NULL,
  `plan_name` VARCHAR(255) DEFAULT NULL,
  `amount_invested_trx` DECIMAL(20,8) NOT NULL,
  `amount_invested_frs` DECIMAL(10,2) NOT NULL,
  `expected_return_frs` DECIMAL(10,2) DEFAULT 0.00,
  `duration_days` INT(11) DEFAULT NULL,
  `payout_date` DATETIME DEFAULT NULL,
  `current_return_frs` DECIMAL(10,2) DEFAULT 0.00,
  `transaction_hash` VARCHAR(255) DEFAULT NULL,
  `status` ENUM('pending','completed','active','paid_out','failed') DEFAULT 'pending',
  `date_invested` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `investments_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- TABLE: notifications
DROP TABLE IF EXISTS `notifications`;
CREATE TABLE `notifications` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `user_id` INT(11) NOT NULL,
  `message` TEXT NOT NULL,
  `type` VARCHAR(20) NOT NULL,
  `is_read` TINYINT(1) DEFAULT 0,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `notifications_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- TABLE: transactions
DROP TABLE IF EXISTS `transactions`;
CREATE TABLE `transactions` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `user_id` INT(11) DEFAULT NULL,
  `amount` DECIMAL(10,2) DEFAULT NULL,
  `currency` VARCHAR(10) DEFAULT NULL,
  `status` ENUM('pending','completed','failed') DEFAULT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `type` VARCHAR(50) DEFAULT 'deposit',
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `transactions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- TABLE: withdrawals
DROP TABLE IF EXISTS `withdrawals`;
CREATE TABLE `withdrawals` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `user_id` INT(11) NOT NULL,
  `amount_fcf` DECIMAL(15,2) NOT NULL,
  `wallet_address` VARCHAR(255) NOT NULL,
  `status` ENUM('pending','completed','failed','processing') NOT NULL DEFAULT 'pending',
  `transaction_hash` VARCHAR(255) DEFAULT NULL,
  `notes` TEXT DEFAULT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `processed_at` TIMESTAMP NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `withdrawals_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

SET FOREIGN_KEY_CHECKS=1;
