# Core Tenets
1. We preference security, durability, availability, in that order.
2. Never put secrets/credentials in code, but they can go in environment files.
3. For external interfaces and APIs we always favor backwards compatabiliy. When designing external interfaces, always think about the consumer, and design foward+backward compatible intefaces, this means we support clients with Tolerant-Reader pattern.

# Project overview
This is a Golang based HashiCorp Vault secrets engine that supports OpenLDAP.

# References
Use context7 tools for looking at documentation and API guides!

# Coding
## Codebase norms
1. Always follow the folder structure in the source code
2. Always understand the cultural norms in the code (style, naming, organization) and use that.

## Scratchpad for plans and todos
If you need to write markdown files or scratch space write them in ./scratchpads folder. If you need to write examples to test something also write them in ./scratchpads folder

Track your todos in scratchpads/todos/todo-<today's date>.md

As you go through the todos list if they are done check them off in the markdown file.

## Code commenting
Dont exessively comment code stick to good functions that are not overly complex.
When creating documentation in-code create on functions and classes but avoid putting inline comments unless it is critical to do so!