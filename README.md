# Projekt zaliczeniowy: Serwer usługi DHCP

## Nazwa i opis projektu
Projekt to implementacja serwera protokołu dynamicznego konfigurowania węzłów sieciowych (DHCP) w języku C. Serwer w pełni obsługuje standardowy proces przypisywania adresów IP (cykl DORA - Discover, Offer, Request, Acknowledge), poprawne zwalnianie zasobów (Release) oraz wysyłanie odmowy (NAK) w przypadku nieautoryzowanych lub błędnych żądań o adres IP z puli.

## Zawartość plików źródłowych
Projekt został podzielony na moduły, aby zachować czytelność kodu i separację logiki:
* `dhcp_server.c` – Główny plik programu. Zawiera główną pętlę serwera.
* `dhcp_handler.c` – Funkcje odpowiedzialne za budowanie i wysyłanie odpowiednich pakietów DHCP (OFFER, ACK, NAK) w zależności od otrzymanych żądań od klienta.
* `dhcp_options.c` – Zestaw funkcji pomocniczych do obsługi opcji DHCP wewnątrz struktury pakietu.
* `ip_pool.c` – Logika zarządzania pulą adresów IP. Obsługuje tablicę dzierżaw (leases), weryfikuje dostępność adresów, przypisuje je do adresów MAC oraz kontroluje czas ich wygaśnięcia.
* `dhcp.h` – Plik nagłówkowy zawierający definicje stałych, definicję struktury pakietu `dhcp_packet` oraz deklaracje funkcji.
* `test_dhcp.py` – Skrypt testowy napisany w języku Python, symulujący zachowanie klienta DHCP (wysyłanie zapytań, potwierdzanie, zwalnianie oraz wymuszanie błędów w celu testu NAK).

## Kompilacja i sposób uruchomienia
```bash
gcc dhcp_server.c dhcp_options.c ip_pool.c dhcp_handler.c -o dhcp_server
```

```bash
sudo ./dhcp_server
```