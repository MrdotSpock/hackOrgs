Rámce se od sebe poznají podle flagu _DS-status_:
Pokud platí `pkt[Dot11].FCfield & "to-DS"`, je to rámec z klienta na AP, pak MAC adresa zdroje je `pkt[Dot11].addr2` a cíle `.addr3`
Pokud naopak `... & "from-DS"`, pak zdroj je `.addr3` a cíl `.addr1`
(Vypozorováno podle wiresharku)

Podle `pkt[Dot11].type` se pozná, co je to za rámce:  1 je řídící, 0 jsou management rámce (třeba Beacon), 2 datové
