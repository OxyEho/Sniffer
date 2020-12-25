# Sniffer

Утилита для просмотра и записи интернет трафика с простой фильрацией

## Установка

    git clone https://github.com/OxyEho/Sniffer

## Запуск 

    python3 -m sniffer [-f] [-n] [-a] [--file_size] [--timer] [--ips] [--macs] [--net] [--ip] [--tcp] [--udp] [--others]

    Опция -f Название файла, в который будет записан трафик
    
    Опция -n Количевто пакетов, которое будет записано
    
    Опция -a Записывать трафик бесконечно
    
    Опция --file_size Максимальный размер файла для записи(в байтах)
    
    Опция --timer Интервал времени для создания нового файла
    
    Опция --ips IP адреса, пакеты которых нужно записать, остальные игнорируются
    
    Опция --macs MAC адреса, пакеты которых нужно записать, остальные игнорируются
    
    Опция --net Указывает сеть и маску, будут записаны пакеты только от отправителей в это сети
    
           пример 0.0.0.0/0
    
    Опция --ip Записывать только IP пакеты
    
    Опция --tcp Записывать только TCP пакеты
    
    Опция --udp Записывать только UDP пакеты
    
    Опция --others Записывать пакеты не только перечисленные выше(по умолчанию записываются все пакеты)
       

#### Пример работы sniffer

    sudo python3 -m sniffer -n 1

    Ethernet frame:
        Source MAC: 04:D3:B0:02:D1:2C
        Destination MAC: F0:B4:D2:D0:04:DE
        Protocol: 8

        IP packet:
                Version: 4
                Header length: 20
                Time to live: 64
                Source Ip: 192.168.1.152
                Destination Ip: 140.82.112.26
                Protocol: 6
                Checksum: 46381

                TCP packet:
                        Source port: 53450
                        Destination port: 443
                        Sequence: 3764902982
                        Acknowledgement: 61526629
                        Reserved: 128
                        Flags: URG: 0 ACK: 1
                               PSH: 0 RST: 0
                               SYN: 0 FIN: 0
                        Window: 501
                        Checksum: 16608
                        Urgent pointer: 0


    