# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
A company stores employee salaries using Paillier encryption. 
Encrypt three salaries, calculate the total and average salary using homomorphic operations without decrypting individual salaries, and allow only the HR Manager to decrypt the aggregate results. 
Other roles must be denied access to the results.
'''

from phe import paillier

public_key, private_key = paillier.generate_paillier_keypair()

salaries = [40000, 50000, 60000]

encrypted_sals = [public_key.encrypt(salary) for salary in salaries]

print("Encrypted salaries created successfully.")

for i, encrypted_salary in enumerate(encrypted_sals):
    print(f"Employee {i + 1} ciphertext:", encrypted_salary.ciphertext())
     
encrypted_total = encrypted_sals[0]

for encrypted_salary in encrypted_sals[1:]:
    encrypted_total += encrypted_salary
    
encrypted_avg = encrypted_total * (1 / len(salaries))

role = input("Enter your role: ").strip().lower()

if role == "hr":
    total = private_key.decrypt(encrypted_total)
    avg = private_key.decrypt(encrypted_avg)
    print("Total Salary:", total)
    print("Average Salary:", avg)
    
elif role == "employee":
    print("Access denied! Aggregate results are restricted.")

else:
    print("Invalid role!")
