import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateCatDto } from './dto/create-cat.dto';
import { UpdateCatDto } from './dto/update-cat.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Cat } from './entities/cat.entity';
import { Breed } from 'src/breeds/entities/breed.entity';


@Injectable()
export class CatsService {

  constructor(
    @InjectRepository(Cat)
    private catRepository: Repository<Cat>,

    @InjectRepository(Breed)
        private breedRepositoy: Repository<Breed>
  ) {}

  async create(createCatDto: CreateCatDto) {

    const breed = await this.breedRepositoy.findOneBy({ name: createCatDto.breed});

    if(!breed){
      throw new BadRequestException('Breed not found');
    }

    return await this.catRepository.save({
      ...createCatDto,
      breed
    });
  }

  async findAll() {
    return await this.catRepository.find();
  }

  async findOne(id: number) {
    return await this.catRepository.findOneBy({id})
  }

  async update(id: number, updateCatDto: UpdateCatDto) {
    // return await this.catRepository.update(id, updateCatDto);
    return;
  }

  async remove(id: number) {
    return await this.catRepository.softDelete({id});
  }
}
