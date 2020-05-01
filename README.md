# 스프링부트2를 통한 oauth2 클라이언트와 리소스 서버 구현 

- 스프링 부트의 2.x 버전에서 OAuth 2.0을 통해 클라이언트와 리소스 서버를 구현해본 프로젝트입니다.
- 데이터베이스로는 MySql을 사용하였으며, 데이터베이스 툴은 HeidiSQL을 사용했고, 필요한 테이블 구조는 아래와 같습니다.

## [user 테이블] 
- 프로젝트에서 사용한 사용자 테이블입니다.
```sql
CREATE TABLE `user` (
	`user_no` INT(11) NOT NULL AUTO_INCREMENT,
	`identity` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`password` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`name` VARCHAR(50) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`created_date` DATETIME NULL DEFAULT NULL,
	`email` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`principal` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`social_type` VARCHAR(50) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`address_1` VARCHAR(50) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`address_2` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`address_3` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`phone` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`updated_date` DATETIME NULL DEFAULT NULL,
	`mileage` INT(7) NULL DEFAULT NULL,
	`status` INT(11) NULL DEFAULT NULL,
	`grade` INT(11) NULL DEFAULT NULL,
	`auth` VARCHAR(50) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	PRIMARY KEY (`user_no`) USING BTREE
)
COLLATE='utf8mb4_general_ci'
ENGINE=InnoDB
AUTO_INCREMENT=17
;

```

## [oauth_client_details] 
 - /ouath2/authorize?~ 로 인증 요청을 보낼 때, DB에 저장되어 있는 클라이언트 정보를 확인하기 위한 테이블

```sql
CREATE TABLE `oauth_client_details` (
	`client_id` VARCHAR(256) NOT NULL COLLATE 'utf8_general_ci',
	`resource_ids` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`client_secret` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`scope` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`authorized_grant_types` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`web_server_redirect_uri` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`authorities` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`access_token_validity` INT(11) NULL DEFAULT NULL,
	`refresh_token_validity` INT(11) NULL DEFAULT NULL,
	`additional_information` VARCHAR(4096) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`autoapprove` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	PRIMARY KEY (`client_id`) USING BTREE
)
COLLATE='utf8_general_ci'
ENGINE=InnoDB
;

```

## 아래부터는 JWT 토큰을 이용하지 않고 bear 방식을 통해 oauth 인증을 할 때, 서버를 재시작 하게되면 정보가 refresh 되기 때문에 관련 정보를 DB로 관리해주기 위한 테이블 입니다.

## [oauth_access_token]

```sql
CREATE TABLE `oauth_access_token` (
	`token_id` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`token` VARBINARY(256) NULL DEFAULT NULL,
	`authentication_id` VARCHAR(256) NOT NULL COLLATE 'utf8_general_ci',
	`user_name` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`client_id` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`authentication` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`refresh_token` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	PRIMARY KEY (`authentication_id`) USING BTREE
)
COLLATE='utf8_general_ci'
ENGINE=InnoDB
;

```

## [oauth_approvals]

```sql
CREATE TABLE `oauth_approvals` (
	`userId` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`clientId` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`scope` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`status` VARCHAR(10) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`expiresAt` TIMESTAMP NULL DEFAULT NULL,
	`lastModifiedAt` TIMESTAMP NULL DEFAULT NULL
)
COLLATE='utf8_general_ci'
ENGINE=InnoDB
;

```

## [oauth_client_token]

```sql
CREATE TABLE `oauth_client_token` (
	`token_id` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`token` VARBINARY(256) NULL DEFAULT NULL,
	`authentication_id` VARCHAR(256) NOT NULL COLLATE 'utf8_general_ci',
	`user_name` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`client_id` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	PRIMARY KEY (`authentication_id`) USING BTREE
)
COLLATE='utf8_general_ci'
ENGINE=InnoDB
;

```

## [oauth_code]

```sql
CREATE TABLE `oauth_code` (
	`code` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`authentication` VARBINARY(256) NULL DEFAULT NULL
)
COLLATE='utf8_general_ci'
ENGINE=InnoDB
;

```

## [oauth_refresh_token]

```sql
CREATE TABLE `oauth_refresh_token` (
	`token_id` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`token` VARBINARY(256) NULL DEFAULT NULL,
	`authentication` VARBINARY(256) NULL DEFAULT NULL
)
COLLATE='utf8_general_ci'
ENGINE=InnoDB
;

```
