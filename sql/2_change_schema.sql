ALTER TABLE `book`
    ADD COLUMN `lending_id` varchar(255) NULL,
    ADD COLUMN `member_id` varchar(255) NULL,
    ADD COLUMN `due` datetime(6) NULL,
    ADD COLUMN `lent_at` datetime(6) NULL;
ALTER TABLE `book` ADD INDEX `idx_book_due` (`due`);

INSERT INTO `book` (`id`, `lending_id`, `member_id`, `due`, `lent_at`)
    SELECT `book_id`, `id`, `member_id`, `due`, `created_at` FROM `lending` AS l
    ON DUPLICATE KEY UPDATE
                         `lending_id` = l.id,
                         `member_id` = l.member_id,
                         `due` = l.due,
                         `lent_at` = l.created_at;

DROP TABLE lending;
