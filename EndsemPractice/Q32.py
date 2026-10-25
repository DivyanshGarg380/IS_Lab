# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    Develop a menu-driven Python program for a secure election system.

    Election Officer
        - Register voter IDs.
        - Store an HMAC-SHA256 token for each voter ID to prevent duplicate voting.
        - Use Diffie–Hellman to establish a shared secret between the election officer and ballot system.
    
    Voter
        - Cast a vote for candidate 1, 2, or 3.
        - Encrypt the vote using ElGamal with the election public key.
        - Generate a SHA-256 digest of the encrypted ballot.
    
    Auditor
        - Search for a ballot using its ballot ID.
        - Verify its SHA-256 digest.
        - Display the encrypted ballot in hexadecimal form.
    
    Tally Officer
        - Decrypt ballots and count votes for each candidate.
        - Ensure that a voter cannot vote twice.
'''

import hashlib
import hmac

p = 467
g = 2

officer_private = 127
system_private = 213

officer_public = pow(g, officer_private, p)
system_public = pow(g, system_private, p)

officer_secret = pow(system_public, officer_private, p)
system_secret = pow(officer_public, system_private, p)

print("DH Shared Secret Verified:", officer_secret == system_secret)

x = 127
y = pow(g, x, p)

voter_key = b"voter-search-key"

voters = []
ballots = []

while True:
    print("\n1. Register voter")
    print("2. Cast vote")
    print("3. Audit ballot")
    print("4. Tally votes")
    print("5. Exit")

    choice = input("Choose: ")
    
    if choice == "1":
        voter_id = input("Voter ID: ")
        token = hmac.new(voter_key, voter_id.encode(), hashlib.sha256).hexdigest()
        
        if token in voters:
            print("Voter already registered")
        else:
            voters.append(token)
            print("Voter registered")
            
    elif choice == "2":
        voter_id = input("Voter ID: ")
        token = hmac.new(voter_key, voter_id.encode(), hashlib.sha256).hexdigest()
        
        if token not in voters:
            print("Voter not registered")
            continue
        
        alread_voted = False
        for ballot in ballots:
            if ballot["voter"] == token:
                already_voted = True
                break
            
        if already_voted:
            print("Voter has already voted")
            continue

        vote = input("Candidate (1, 2, 3): ")
        vote = int(vote)
        
        k = 53 
        c1 = pow(g, k, p)
        c2 = (vote * pow(y, k, p)) % p

        encrypted_ballot = (c1, c2)
        digest = hashlib.sha256((str(c1) + "|" + str(c2)).encode()).hexdigest()
        
        ballot_id = "B" + str(len(ballots) + 1)
        
        ballots.append({
            "id": ballot_id,
            "voter": token,
            "cipher": encrypted_ballot,
            "hash": digest
        })

        print("Ballot ID:", ballot_id)
        print("Vote encrypted and submitted")

    elif choice == "3":
        ballot_id = input("Ballot ID: ")
        found = False

        for ballot in ballots:
            if ballot["id"] == ballot_id:
                found = True

                c1, c2 = ballot["cipher"]
                print("Encrypted ballot:", str(c1).encode().hex(), str(c2).encode().hex())

                digest = hashlib.sha256((str(c1) + "|" + str(c2)).encode()).hexdigest()
                
                if digest == ballot["hash"]:
                    print("Integrity verified")
                else:
                    print("Ballot tampered")

                break
        
        if not found:
            print("Ballot not found")
            
    elif choice == "4":
        count = {1: 0, 2: 0, 3: 0}
        for ballot in ballots:
            c1, c2 = ballot["cipher"]

            digest = hashlib.sha256((str(c1) + "|" + str(c2)).encode()).hexdigest()

            if digest != ballot["hash"]:
                print("Skipping tampered ballot:", ballot["id"])
                continue

            shared = pow(c1, x, p)
            vote = (c2 * pow(shared, -1, p)) % p

            if vote in count:
                count[vote] += 1

        print("Candidate 1:", count[1])
        print("Candidate 2:", count[2])
        print("Candidate 3:", count[3])

    elif choice == "5":
        break

    else:
        print("Invalid choice")