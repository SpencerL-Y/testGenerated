#include "../include/Cryptor.hpp"
#include <stdlib.h>
#include <iostream>
#include <string>
int main(){
    Cryptor cryptor;
    Cryptor cryptor1;
    std::string key = "thisiskey";
    std::string key2 = "thisiskey";
    std::string wrongKey = "thisis";
    char* out = (char*)malloc(100*sizeof(char));
    std::string origin = "serialization::archi���C�";
    cryptor.aes_encrypt((char*)origin.c_str(), (char*)key.c_str(), out);
    std::cout << out << std::endl;
    char* outout = (char*)malloc(100*sizeof(char));
    cryptor1.aes_decrypt(out, (char*)key2.c_str(), outout);

    std::cout << outout << std::endl;
    free(out);
    free(outout);
    std::string pri, pub;
    cryptor.createRSAKeyPair(pub, pri);
    std::cout << "pri:\n" << pri << std::endl;
    std::cout << "pub:\n" << pub << std::endl;
    //pri = "false";
    //std::string pubkey = "MIIBCAKCAQEAvT1ytMNiQo+6GREbw4NzhzbXMPI+tZ49S/tvQpNzy2BXqBWnNVvvKsqh4OCGE9mA9US3Ei3SCzhJFhsQGWL5ut71wmPOCyFjSa70985LnuRLlcBbOvO5p3Hhf3ZguwUZRy3HgMBfSy9l86IurSBW3kupzP6ITBy8KCpoJ0h6kEcp4ZpnXFucF8NYuTE5bge88bC/5CrHIPO87L45rTsF2TCx5XHfH7PHPmH2u+ppND56tlCwazKRWpPgHRxn6oQf4OdmvnVA6y6SpotwWDzQhWZucn3JRWV9El6D8G1mn+WNiEcbSkQE2H8omGoo97HFz9CbAWULyLB6OG7B1UajjQIBAw==";
    out = (char*)malloc(sizeof(char)*1000);
    outout = (char*)malloc(sizeof(char)*1000);
    origin = "this is me";
    std::cout << origin << std::endl;
    std::string cypher = cryptor.rsa_pubkey_encrypt(origin, pub);
    std::cout << "out: " << cypher << std::endl;
    //std::string prikey = "IIEowIBAAKCAQEAvT1ytMNiQo+6GREbw4NzhzbXMPI+tZ49S/tvQpNzy2BXqBWnNVvvKsqh4OCGE9mA9US3Ei3SCzhJFhsQGWL5ut71wmPOCyFjSa70985LnuRLlcBbOvO5p3Hhf3ZguwUZRy3HgMBfSy9l86IurSBW3kupzP6ITBy8KCpoJ0h6kEcp4ZpnXFucF8NYuTE5bge88bC/5CrHIPO87L45rTsF2TCx5XHfH7PHPmH2u+ppND56tlCwazKRWpPgHRxn6oQf4OdmvnVA6y6SpotwWDzQhWZucn3JRWV9El6D8G1mn+WNiEcbSkQE2H8omGoo97HFz9CbAWULyLB6OG7B1UajjQIBAwKCAQB+KPcjLOwsX9FmC2fXrPeveeTLTCnOaX4yp5+Bt6KHlY/FY8TOPUochxaV6wQNO6tOLc9hc+Fc0DC5Z2AQ7KZ8lKPW7TQHa5eGdKNP3t0UmDJj1ZInTSZvoUD/pEB8rhDaHoUAgD+HdO6ibB8eFY8+3Rvd/wWIEygaxvAaMFG1g6EbaUo/N3SQ16GcMwS3C3P5r2SBK1eilzUZKUNy5FgZuHNh/jSmuaa9XfdlxfbqfjkW0TQcHVn0JOaFdsaNApzuhLLlcIcpyoBUpoPFUu5RpBbWPflFyVo59C4BgIUW1IEDn5hVJCH8UYyWJL1hbct6cwNf3htKXkNsG1sE4ZgrAoGBAN3fez7kf5WdwT/iWCe3yyQefnTPsQHRuadjmVtcgv9lnht8bNhlR16dvfP3DB+oJN4c0NNj5OBuPZxwGBjtVtv3X+WQTeeVAHeJEyI8pIePir2/Gh9+6OXjg3L8hfuYxZT0ZPVcwln3Us2ziuU0CzclQ5xRgEbHGHQHgDBcdftxAoGBANpZATkZCNegvqZsjIqjq2rcqzRSuMHbV0XjZvkkYYJM/elWB7fAVe6Elw+sNVcsXEb3Rg7dIan+Hunk0iUpqViDwHTV/o6Xflqefohzm+N7ZY5yBrPdzo/X7MvxpqNk4TcOcsFty3fmsggDqCexgd1y4HmgF5wSCqEOxYjxfkPdAoGBAJPqUintqmO+gNVBkBp6h21pqaM1IKvhJm+Xu5I9rKpDvrz9neWY2j8T0/f6CBUawz694IztQ0BJfmhKurtI5JKk6pkK3ppjVaUGDMF9wwUKXH5/Zr+p8JlCV6H9rqe7LmNNmKOTLDv6NzPNB0N4B3oY172LqtnaEE1aVXWS+VJLAoGBAJGQq3tmBeUV1G7zCFxtHPHociLh0IE85NlCRKYYQQGIqUY5WnqAOUmtugpyzjodktn6LrSTa8apafFDNsNxG5BX1aM5VF8PqZG+/wWiZ+z87l72ryKT3wqP8zKhGcJDQM9e9yueh6VEdrACcBp2VpOh6vvAD71hXGtfLltLqYKTAoGBALpe2ruWH2nQkjg6eyuaVsO2oOpHXK6y7CnD/H60NsdwLStQg0UazLgMdPxiy6C9K3tX2KtP2szZaabOI954qvB+gxUZlnCSxE8LQXXpgU67qrt8flfSj0F9ak5xivFCHj209GqZWQLjMi51Snc4Bg6JmJVYf9R9wNwquGmFnvvz";
    std::string clear = cryptor.rsa_prikey_decrypt(cypher, pri);
    std::cout << "outout: " << clear << std::endl;
    free(out);
    free(outout);
    std::string cipher = cryptor.sha1_encrypt(origin, pri);
    std::cout << "cipher: " << cipher << std::endl;
    std::string outoutStr = cryptor.sha1_decrypt(cipher, pub);
    std::cout << "outoutStr: " << outoutStr << std::endl;
    return 0;
}