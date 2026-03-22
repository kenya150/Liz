/// <reference types="jasmine" />
import { EncryptionService } from './encryptionService';

describe('EncryptionService', () => {
  let service: EncryptionService;

  beforeEach(() => {
    service = new EncryptionService();
  });

  it('debe cifrar y descifrar datos correctamente', async () => {
    const text = 'Hola Mundo 123';
    const encrypted = await service.encrypt(text);
    expect(encrypted).toContain(':');

    const decrypted = await service.decrypt(encrypted);
    expect(decrypted).toBe(text);
  });

  it('debe generar IVs diferentes para el mismo texto', async () => {
    const text = 'texto secreto';
    const encrypted1 = await service.encrypt(text);
    const encrypted2 = await service.encrypt(text);

    expect(encrypted1).not.toBe(encrypted2);

    const decrypted1 = await service.decrypt(encrypted1);
    const decrypted2 = await service.decrypt(encrypted2);
    expect(decrypted1).toBe(text);
    expect(decrypted2).toBe(text);
  });

  it('debe lanzar error con formato de datos corruptos', async () => {
    const corruptData = 'iv_invalido:data_invalida';
    await expectAsync(service.decrypt(corruptData)).toBeRejectedWithError(/Fallo en el proceso de descifrado/);
  });

  it('debe lanzar error si falta el IV', async () => {
    const invalidFormat = 'solo_data';
    await expectAsync(service.decrypt(invalidFormat)).toBeRejectedWithError(/Formato de datos cifrados inválido/);
  });

  it('debe manejar strings vacíos', async () => {
    const empty = '';
    const encrypted = await service.encrypt(empty);
    expect(encrypted).toBe('');

    const decrypted = await service.decrypt(empty);
    expect(decrypted).toBe('');
  });
});
