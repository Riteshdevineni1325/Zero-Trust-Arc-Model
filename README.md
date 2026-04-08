Zero-Trust-Arc-Mod-V01
This project presents the design and implementation of a Zero Trust Security System using Python and PostgreSQL. The system is built on the principle of “never trust, always verify”, ensuring that every user request is authenticated and authorized before access is granted.

The application provides secure user registration and login functionalities using JWT (JSON Web Token)–based authentication. It supports role-based access control, where users are categorized as normal users or administrators. To prevent unauthorized privilege escalation, administrator account creation requires validation using existing admin credentials.

A Zero Trust middleware layer is implemented to validate every incoming request by verifying the token, user identity, and device information. Additional security measures such as optional IP address validation and device checks enhance protection against unauthorized access and token misuse.

The system also includes administrative controls that allow authorized administrators to manage users, including the ability to delete user accounts with appropriate safeguards. The backend is powered by Flask, while PostgreSQL is used for efficient and reliable data storage.

Overall, the project demonstrates a practical implementation of modern security principles, combining authentication, authorization, and continuous verification to build a secure and scalable web application.
