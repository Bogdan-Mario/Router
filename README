Prezentare generală
Acesta este un router de rețea scris în C care procesează pachete IPv4, cereri/răspunsuri ARP și mesaje ICMP. Routerul efectuează forwardare de pachete, rezolvare ARP și generează răspunsuri ICMP atunci când este necesar.

Funcționalități principale
Forwardare pachete IPv4: Dirijează pachetele pe baza unui tabel de rutare

Rezolvare ARP: Gestionează cererile și răspunsurile ARP, menținând un cache ARP

Suport ICMP: Generează răspunsuri pentru:

Cereri echo (ping)

Mesaje "TTL expired"

Mesaje "Destination unreachable"

Căutare prefix lung: Utilizează o structură trie binară pentru căutare eficientă în tabela de rutare

Cozi de așteptare: Păstrează pachete în așteptarea rezolvării ARP

Componente principale
1. Tabela de rutare
Încărcată din fișier la pornire

Organizată într-un trie binar pentru potrivirea eficientă a prefixului cel mai lung

Suportă masti de rețea standard

2. Cache ARP
Actualizat dinamic pe măsură ce se primesc răspunsuri ARP

Folosit pentru a rezolva adrese MAC pentru IP-urile următoare

3. Procesarea pachetelor
Prelucrare frame-uri Ethernet (atât IPv4 cât și ARP)

Validare antet IPv4 și verificare checksum

Gestionare TTL și decrementare

Generare mesaje ICMP

Protocol suportate
Ethernet: Encapsulare frame-uri

IPv4: Forwardare pachete cu verificare antet

ARP: Rezolvare adrese MAC

ICMP: Raportare erori și răspunsuri echo

Structuri de date utilizate
Trie binar: Pentru căutare eficientă în tabela de rutare

Coadă: Pentru stocarea pachetelor în așteptarea rezolvării ARP

Cache ARP: Stocare bazată pe array

Tabelă de rutare: Array de intrări de rută

Limitări
Dimensiuni maxime fixe pentru tabela de rutare și cache ARP

Implementare bazată de coadă fără prioritizare

Nu suportă IPv6 sau alte protocoale avansate
