# SimpTCP

https://github.com/SimpTCP/SimpTCP

# Avancement

A priori tout fonctionne : SYN/SYNACK/ACK + DATA/ACK dans les deux sens + FIN/FINACK/ACK. Par contre, aucun check n'est fait sur la bonne utilisation de l'API : appel du send alors qu'on est dans l'état close, etc... C'est donc à terminer. Nous n'avons pas encore testé avec le libc_socket modifié permettant de simuler les pertes de packet sur le réseau.

