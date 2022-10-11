CREATE TABLE theme(
   Id_theme INT AUTO_INCREMENT,
   title VARCHAR(255),
   img_src VARCHAR(255),
   is_deleted BOOLEAN,
   PRIMARY KEY(Id_theme)
);

CREATE TABLE tag(
   Id_tag INT AUTO_INCREMENT,
   title VARCHAR(255),
   is_deleted BOOLEAN,
   PRIMARY KEY(Id_tag)
);

CREATE TABLE role(
   Id_role INT AUTO_INCREMENT,
   title VARCHAR(255),
   is_deleted BOOLEAN,
   PRIMARY KEY(Id_role)
);

CREATE TABLE appUser(
   Id_appUser INT AUTO_INCREMENT,
   pseudo VARCHAR(255),
   is_deleted BOOLEAN,
   Id_role INT,
   PRIMARY KEY(Id_appUser),
   UNIQUE(pseudo),
   FOREIGN KEY(Id_role) REFERENCES role(Id_role)
);

CREATE TABLE account(
   Id_account INT AUTO_INCREMENT,
   login VARCHAR(255),
   password VARCHAR(255),
   is_deleted BOOLEAN,
   Id_appUser INT,
   PRIMARY KEY(Id_account),
   UNIQUE(Id_appUser),
   UNIQUE(login),
   FOREIGN KEY(Id_appUser) REFERENCES appUser(Id_appUser)
);

CREATE TABLE article(
   Id_article INT AUTO_INCREMENT,
   title VARCHAR(255),
   content TEXT,
   created_at DATETIME,
   updated_at DATETIME,
   is_deleted BOOLEAN,
   Id_appUser INT,
   Id_theme INT,
   PRIMARY KEY(Id_article),
   FOREIGN KEY(Id_appUser) REFERENCES appUser(Id_appUser),
   FOREIGN KEY(Id_theme) REFERENCES theme(Id_theme)
);

CREATE TABLE image(
   Id_image INT AUTO_INCREMENT,
   src VARCHAR(255),
   alt VARCHAR(255),
   is_deleted BOOLEAN,
   Id_article INT,
   PRIMARY KEY(Id_image),
   FOREIGN KEY(Id_article) REFERENCES article(Id_article)
);

CREATE TABLE comment(
   Id_comment INT AUTO_INCREMENT,
   title VARCHAR(255),
   content TEXT,
   created_at DATETIME,
   is_approved BOOLEAN,
   is_deleted BOOLEAN,
   Id_appUser INT,
   Id_article INT,
   PRIMARY KEY(Id_comment),
   FOREIGN KEY(Id_appUser) REFERENCES appUser(Id_appUser),
   FOREIGN KEY(Id_article) REFERENCES article(Id_article)
);

CREATE TABLE article_tag(
   Id_article INT,
   Id_tag INT,
   PRIMARY KEY(Id_article, Id_tag),
   FOREIGN KEY(Id_article) REFERENCES article(Id_article),
   FOREIGN KEY(Id_tag) REFERENCES tag(Id_tag)
);
