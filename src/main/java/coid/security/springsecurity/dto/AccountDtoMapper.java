package coid.security.springsecurity.dto;

import coid.security.springsecurity.dmain.Account;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper
public interface AccountDtoMapper {

	AccountDtoMapper INSTANCE = Mappers.getMapper(AccountDtoMapper.class);

	Account create(AccountDto accountDto);
}
